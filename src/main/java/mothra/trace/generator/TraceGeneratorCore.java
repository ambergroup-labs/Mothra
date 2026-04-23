/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package mothra.trace.generator;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;

import java.util.*;
import java.util.Objects;

import db.Transaction;
import ghidra.framework.model.Project;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.stack.TraceStack;
import ghidra.trace.model.stack.TraceStackFrame;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.model.time.TraceSnapshot;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mothra.trace.builder.ToyDBTraceBuilder;
import mothra.trace.data.DataStore;
import mothra.util.MothraLog;

/**
 * TraceGeneratorCore - Core trace database generation logic for Mothra plugin
 *
 * This class provides the core functionality to generate Ghidra trace databases
 * from Ethereum transaction data stored in DataStore. It creates:
 * - Snapshot 0: Initial state with all contracts deployed
 * - Snapshots 1-N: After each instruction execution
 *
 * Usage:
 *   TraceGeneratorCore generator = new TraceGeneratorCore(dataStore, language);
 *   generator.generateTraceDatabase(txHash, outputFile);
 */
public class TraceGeneratorCore {

    private static final long STACK_TOP = 0x2000L;  // Stack pointer initial value
    private static final int STACK_ITEM_SIZE = 32;  // EVM stack items are 256-bit (32 bytes)

    // Memory region base addresses for EVM execution data
    private static final long CALLDATA_BASE = 0x40000000L;   // Calldata storage
    private static final long EVM_MEMORY_BASE = 0x50000000L; // EVM memory storage
    private static final long EVM_STACK_BASE = 0x60000000L;  // EVM stack data storage
    private static final long STORAGE_BASE = 0x70000000L;    // Storage key-value pairs
    private static final long GAS_BASE = 0x80000000L;        // Gas info (gas at 0x80000000, gasCost at 0x80000004)

    private final DataStore dataStore;
    private final String language;

    /**
     * Create a new trace generator
     *
     * @param dataStore DataStore containing transaction data
     * @param language Ghidra language ID (e.g., "evm:256:default")
     */
    public TraceGeneratorCore(DataStore dataStore, String language) {
        this.dataStore = dataStore;
        this.language = language;
    }

    /**
     * Generate a trace database file
     *
     * @param txHash Transaction hash (for naming and metadata)
     * @param outputFile Output file path (.gzf)
     * @throws Exception if generation fails
     */
    public void generateTraceDatabase(String txHash, String outputFile) throws Exception {
        generateTraceDatabase(txHash, outputFile, null, null, TaskMonitor.DUMMY);
    }

    /**
     * Generate a trace database file with optional static mappings
     *
     * @param txHash Transaction hash (for naming and metadata)
     * @param outputFile Output file path (.gzf)
     * @param project Ghidra project (null to skip static mappings)
     * @param programName Program database name (null to skip static mappings)
     * @throws Exception if generation fails
     */
    public void generateTraceDatabase(String txHash, String outputFile,
                                     Project project, String programName) throws Exception {
        generateTraceDatabase(txHash, outputFile, project, programName, TaskMonitor.DUMMY);
    }

    /**
     * Generate a trace database file with optional static mappings and progress monitoring
     *
     * @param txHash Transaction hash (for naming and metadata)
     * @param outputFile Output file path (.gzf)
     * @param project Ghidra project (null to skip static mappings)
     * @param programName Program database name (null to skip static mappings)
     * @param monitor Task monitor for progress reporting
     * @throws Exception if generation fails
     */
    public void generateTraceDatabase(String txHash, String outputFile,
                                     Project project, String programName,
                                     TaskMonitor monitor) throws Exception {
        String traceName = "EthTx_" + txHash.substring(0, Math.min(16, txHash.length()));

        try (ToyDBTraceBuilder builder = new ToyDBTraceBuilder(traceName, language)) {
            try (Transaction tx = builder.startTransaction()) {

                // Create contract manager with DataStore
                ContractManager contractMgr = new ContractManager(builder, dataStore);

                // Create snapshot 0 - initial state (40-42%)
                MothraLog.progress(this, "[1] Creating snapshot 0 - Initial state");
                monitor.setMessage("Creating initial snapshot...");
                monitor.setProgress(40);
                TraceThread thread = createInitialSnapshot(builder, txHash, contractMgr);

                monitor.checkCancelled();

                // Create snapshots for each instruction (42-90%)
                MothraLog.progress(this, "[2] Creating instruction snapshots");
                createInstructionSnapshots(builder, thread, contractMgr, dataStore.getInstructionSteps(), monitor);

                monitor.checkCancelled();

                MothraLog.progress(this, "[3] Trace summary");
                printTraceSummary(builder);
                monitor.setProgress(91);

                // Create static mappings if project and program name are provided (91-93%)
                if (project != null && programName != null && !programName.isEmpty()) {
                    MothraLog.progress(this, "[4] Creating static mappings to program database");
                    monitor.setMessage("Creating static mappings...");
                    int mappingCount = contractMgr.createStaticMappingsToProgram(project, programName);
                    if (mappingCount > 0) {
                        MothraLog.info(this, "✓ Created " + mappingCount + " static mapping(s) to " + programName);
                    }
                }
                monitor.setProgress(93);
            }

            monitor.checkCancelled();

            String saveStep = (project != null && programName != null) ? "[5]" : "[4]";
            MothraLog.progress(this, saveStep + " Saving trace to packed database...");
            monitor.setMessage("Saving trace database...");
            saveTraceToPacked(builder, traceName, outputFile);
            monitor.setProgress(95);
        }
    }

    private TraceThread createInitialSnapshot(ToyDBTraceBuilder builder,
                                              String txHash,
                                              ContractManager contractMgr)
            throws Exception {

        MothraLog.info(this, "  → Creating snapshot metadata...");
        TraceSnapshot snapshot = builder.trace.getTimeManager()
            .createSnapshot("Initial - Transaction " + txHash);
        long snapKey = snapshot.getKey();
        Lifespan zeroOn = Lifespan.nowOn(snapKey);

        MothraLog.info(this, "  → Creating root object...");
        TraceObject root = builder.createRootObject(ToyDBTraceBuilder.CTX_DEFAULT, "Session");
        root.setAttribute(zeroOn, "_display", "Ethereum Tx: " + txHash);

        MothraLog.info(this, "  → Creating object model containers...");
        builder.createObjectsModulesContainer();
        builder.createObjectsMemoryContainer();

        MothraLog.info(this, "  → Creating thread...");
        TraceThread thread = builder.createObjectsProcessAndThreads();
        TraceObject threadObj = thread.getObject();
        threadObj.setAttribute(zeroOn, "_tid", 1);
        threadObj.setAttribute(zeroOn, "_name", "evm_main");
        threadObj.setAttribute(zeroOn, "_display", "[1] evm_main [TID: 1]");
        threadObj.setAttribute(zeroOn, "_state", "STOPPED");

        // Set the event thread for the snapshot (for Time window display)
        snapshot.setEventThread(thread);

        MothraLog.info(this, "  → Creating thread registers...");
        builder.createObjectsRegsForThread(thread, zeroOn, builder.host);

        MothraLog.info(this, "  → Adding memory regions...");
        addMemoryRegions(builder);

        MothraLog.info(this, "  → Deploying all contracts...");
        contractMgr.deployAllContracts(snapKey);

        MothraLog.info(this, "  → Setting initial register values...");
        setInitialRegisters(builder, thread, snapKey, contractMgr);

        MothraLog.info(this, "  → Creating stack frame with PC...");
        // Get initial PC address for the stack frame
        Long codeAddress = contractMgr.getCurrentCodeAddress();
        if (codeAddress == null) {
            codeAddress = 0L;
        }
        AddressSpace ramSpace = builder.language.getAddressFactory().getAddressSpace("ram");
        Address initialPcAddr = ramSpace.getAddress(codeAddress);
        builder.createStackWithFrame(thread, snapKey, initialPcAddr);

        // Write initial calldata to RAM
        MothraLog.info(this, "  → Writing initial calldata...");
        TraceMemoryManager memMgr = builder.trace.getMemoryManager();
        String initialCallData = contractMgr.getCurrentCallData();
        if (initialCallData != null) {
            writeCalldataToMemory(memMgr, ramSpace, snapKey, initialCallData);
        }

        // Write empty EVM execution data for initial state
        writeEvmMemoryToRam(memMgr, ramSpace, snapKey, null);
        writeEvmStackToRam(memMgr, ramSpace, snapKey, null);
        writeStorageToRam(memMgr, ramSpace, snapKey, null);
        writeGasInfoToRam(memMgr, ramSpace, snapKey, 0, 0);  // Initial gas values

        MothraLog.info(this, "  ✓ Snapshot 0 created");
        return thread;
    }

    private void addMemoryRegions(ToyDBTraceBuilder builder) throws Exception {
        TraceMemoryManager memMgr = builder.trace.getMemoryManager();
        Lifespan zeroOn = Lifespan.nowOn(0);

        AddressSpace codeSpace = builder.language.getAddressFactory().getAddressSpace("ram");
        AddressSpace stkSpace = builder.language.getAddressFactory().getAddressSpace("stk");

        if (codeSpace == null || stkSpace == null) {
            throw new Exception("Required address spaces not found");
        }

        Address codeStart = codeSpace.getAddress(0x00000000L);
        Address codeEnd = codeSpace.getAddress(0x3FFFFFFFL);
        memMgr.addRegion("Memory[code]", zeroOn, new AddressRangeImpl(codeStart, codeEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.EXECUTE));

        // Stack region
        Address stkStart = stkSpace.getAddress(0x0000L);
        Address stkEnd = stkSpace.getAddress(0x20000);
        memMgr.addRegion("Memory[stack]", zeroOn, new AddressRangeImpl(stkStart, stkEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

        // Calldata region at 0x40000000 (4 bytes length + up to ~64KB data)
        Address calldataStart = codeSpace.getAddress(CALLDATA_BASE);
        Address calldataEnd = codeSpace.getAddress(CALLDATA_BASE + 0x10000L - 1);
        memMgr.addRegion("Memory[calldata]", zeroOn, new AddressRangeImpl(calldataStart, calldataEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

        // EVM memory region at 0x50000000 (4 bytes length + data)
        Address evmMemStart = codeSpace.getAddress(EVM_MEMORY_BASE);
        Address evmMemEnd = codeSpace.getAddress(EVM_MEMORY_BASE + 0x100000L - 1);
        memMgr.addRegion("Memory[memory]", zeroOn, new AddressRangeImpl(evmMemStart, evmMemEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

        // Storage region at 0x70000000 (4 bytes length + key-value pairs * 64 bytes)
        Address storageStart = codeSpace.getAddress(STORAGE_BASE);
        Address storageEnd = codeSpace.getAddress(STORAGE_BASE + 0x100000L - 1);
        memMgr.addRegion("Memory[storage]", zeroOn, new AddressRangeImpl(storageStart, storageEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));

        // Gas info region at 0x80000000 (8 bytes: 4 for gas + 4 for gasCost)
        Address gasStart = codeSpace.getAddress(GAS_BASE);
        Address gasEnd = codeSpace.getAddress(GAS_BASE + 0x100L - 1);
        memMgr.addRegion("Memory[gas]", zeroOn, new AddressRangeImpl(gasStart, gasEnd),
                        Set.of(TraceMemoryFlag.READ, TraceMemoryFlag.WRITE));
    }

    private void setInitialRegisters(ToyDBTraceBuilder builder, TraceThread thread,
                                     long snap, ContractManager contractMgr) throws Exception {
        TraceMemoryManager memMgr = builder.trace.getMemoryManager();
        TraceMemorySpace memSpace = memMgr.getMemoryRegisterSpace(thread, 0, true);

        // Get the current contract's code address
        Long codeAddress = contractMgr.getCurrentCodeAddress();
        if (codeAddress == null) {
            codeAddress = 0L;
        }

        // Set PC = first contract's code address, SP = STACK_TOP
        setRegister(memSpace, builder.language, snap, "PC", codeAddress);
        setRegister(memSpace, builder.language, snap, "SP", STACK_TOP);

        // Update PC in trace object model for "Track program counter" mode
        updateProgramCounterInObjectModel(thread, snap, codeAddress, builder.language);

        // Clear stack registers
        for (int i = 0; i < 8; i++) {
            setRegisterBig(memSpace, builder.language, snap, "r" + i, BigInteger.ZERO);
        }
    }

    private void initializeCallStack(ToyDBTraceBuilder builder, TraceThread thread,
                                     long snap, ContractManager contractMgr) throws Exception {
        try {
            // Get TraceStack
            TraceStack traceStack = builder.trace.getStackManager().getStack(thread, 0, true);

            // Get the current contract's code address
            Long codeAddress = contractMgr.getCurrentCodeAddress();
            if (codeAddress == null) {
                codeAddress = 0L;
            }

            String currentContract = contractMgr.getCurrentContract();

            // Create initial frame at depth 1 (level 0)
            AddressSpace ramSpace = builder.language.getAddressFactory().getAddressSpace("ram");
            Address pcAddr = ramSpace.getAddress(codeAddress);

            TraceStackFrame frame = traceStack.getFrame(snap, 0, true);
            frame.setProgramCounter(Lifespan.nowOn(snap), pcAddr);

            String frameName = "Contract_" + (currentContract != null ? currentContract : "0x?") + "_depth_1";
            frame.setComment(snap, frameName);

            MothraLog.debug(this, "  → Initial call stack frame created: depth=1, level=0, PC=0x" +
                          Long.toHexString(codeAddress));
        } catch (Exception e) {
            MothraLog.error(this, "Error initializing call stack: " + e.getMessage(), e);
        }
    }

    private void createInstructionSnapshots(ToyDBTraceBuilder builder,
                                            TraceThread thread,
                                            ContractManager contractMgr,
                                            List<DataStore.InstructionStep> steps)
            throws Exception {
        createInstructionSnapshots(builder, thread, contractMgr, steps, TaskMonitor.DUMMY);
    }

    private void createInstructionSnapshots(ToyDBTraceBuilder builder,
                                            TraceThread thread,
                                            ContractManager contractMgr,
                                            List<DataStore.InstructionStep> steps,
                                            TaskMonitor monitor)
            throws Exception {

        int totalSteps = steps.size();
        MothraLog.info(this, "  → Total snapshots to create: " + totalSteps);

        // Calculate progress update frequency (every 1% or every 50 snapshots, whichever is larger)
        int updateFrequency = Math.max(50, totalSteps / 100);

        // Progress range for this method: 42% to 90% (48% range)
        final int PROGRESS_START = 42;
        final int PROGRESS_END = 90;
        final int PROGRESS_RANGE = PROGRESS_END - PROGRESS_START;

        int lastDepth = 1;
        long currentPc = 0;
        long currentSp = STACK_TOP;
        long prevSp = STACK_TOP;
        List<BigInteger> stack = new ArrayList<>();

        // Cache current contract and code address (updated when depth changes)
        String currentContract = contractMgr.getCurrentContract();
        Long currentCodeAddress = contractMgr.getCurrentCodeAddress();
        if (currentCodeAddress == null) {
            currentCodeAddress = 0L;
        }

        // Cache frequently accessed objects outside the loop
        TraceMemoryManager memMgr = builder.trace.getMemoryManager();
        TraceMemorySpace memSpace = memMgr.getMemoryRegisterSpace(thread, 0, true);
        AddressSpace ramSpace = builder.language.getAddressFactory().getAddressSpace("ram");
        AddressSpace stkSpace = builder.language.getAddressFactory().getAddressSpace("stk");

        // Track previous values to skip unchanged writes
        String prevMemory = null;
        List<String> prevEvmStack = null;
        Map<String, String> prevStorage = null;
        String prevCallData = null;
        long prevGas = -1;
        long prevGasCost = -1;

        // Track start time for ETA calculation
        long startTime = System.currentTimeMillis();

        // Get TraceStack for call stack management
        TraceStack traceStack = builder.trace.getStackManager().getStack(thread, 0, true);

        // Track call stack frames by depth
        Map<Integer, TraceStackFrame> depthToFrame = new HashMap<>();

        // Track contract address and PC for each depth (for call stack display)
        Map<Integer, String> depthToContract = new HashMap<>();
        Map<Integer, Long> depthToPC = new HashMap<>();

        // Initialize depth 1 tracking
        depthToContract.put(1, currentContract);
        depthToPC.put(1, currentCodeAddress);

        // Track last depth for call stack updates (only update when depth changes)
        int lastCallStackDepth = 0;

        for (int i = 0; i < steps.size(); i++) {
            DataStore.InstructionStep step = steps.get(i);
            int snapNum = i + 1;

            // Check for depth change and update current contract if needed
            if (step.depth != lastDepth) {
                MothraLog.info(this, "  [" + snapNum + "] Depth change: " + lastDepth +
                                 " → " + step.depth);
                TraceModule newModule = contractMgr.advanceToNextContract(snapNum);
                if (newModule != null) {
                    MothraLog.info(this, "  ✓ Active contract changed: " + newModule.getName(snapNum));
                }
                // Update cached values
                currentContract = contractMgr.getCurrentContract();
                currentCodeAddress = contractMgr.getCurrentCodeAddress();
                if (currentCodeAddress == null) {
                    currentCodeAddress = 0L;
                }
                lastDepth = step.depth;

                // Track contract for this depth
                depthToContract.put(step.depth, currentContract);
            }

            // Update PC based on current contract's code address (use cached value)
            currentPc = currentCodeAddress + step.pc;

            // Track PC for current depth
            depthToPC.put(step.depth, currentPc);

            // Update stack from trace
            stack.clear();
            for (String hexValue : step.stack) {
                stack.add(hexToBigInteger(hexValue));
            }
            prevSp = currentSp;
            currentSp = STACK_TOP - (stack.size() * 4);

            // Create snapshot with adjusted PC
            String desc = "After: " + step.op + " @ PC=0x" + Long.toHexString(currentPc) +
                         " (offset=0x" + Long.toHexString(step.pc) + ", depth=" + step.depth + ")";
            TraceSnapshot snapshot = builder.trace.getTimeManager().createSnapshot(desc);
            long snapKey = snapshot.getKey();

            // Set the event thread for the snapshot (for Time window display)
            snapshot.setEventThread(thread);

            // Set register values (using cached memMgr and memSpace)
            setRegister(memSpace, builder.language, snapKey, "PC", currentPc);
            setRegister(memSpace, builder.language, snapKey, "SP", currentSp);

            // Update PC in trace object model for "Track program counter" mode
            updateProgramCounterInObjectModel(thread, snapKey, currentPc, builder.language);

            // Set stack registers (r0-r7 for top 8 values)
            int stackSize = stack.size();
            for (int j = 0; j < 8; j++) {
                if (j < stackSize) {
                    // Stack is stored with top at end of list
                    BigInteger value = stack.get(stackSize - 1 - j);
                    setRegisterBig(memSpace, builder.language, snapKey, "r" + j, value);
                } else {
                    setRegisterBig(memSpace, builder.language, snapKey, "r" + j, BigInteger.ZERO);
                }
            }

            // Write stack to memory
            writeStackToMemory(memMgr, stkSpace, snapKey, prevSp, currentSp, stack);

            // Write EVM execution data to RAM regions (skip unchanged data)
            // Calldata at 0x40000000
            String currentCallData = contractMgr.getCurrentCallData();
            if (currentCallData != null && !Objects.equals(currentCallData, prevCallData)) {
                writeCalldataToMemory(memMgr, ramSpace, snapKey, currentCallData);
                prevCallData = currentCallData;
            }

            // EVM memory at 0x50000000
            if (!Objects.equals(step.memory, prevMemory)) {
                writeEvmMemoryToRam(memMgr, ramSpace, snapKey, step.memory);
                prevMemory = step.memory;
            }

            // EVM stack at 0x60000000
            if (!Objects.equals(step.stack, prevEvmStack)) {
                writeEvmStackToRam(memMgr, ramSpace, snapKey, step.stack);
                prevEvmStack = step.stack != null ? new ArrayList<>(step.stack) : null;
            }

            // Storage at 0x70000000
            if (!Objects.equals(step.storage, prevStorage)) {
                writeStorageToRam(memMgr, ramSpace, snapKey, step.storage);
                prevStorage = step.storage != null ? new HashMap<>(step.storage) : null;
            }

            // Gas info at 0x80000000 (gas) and 0x80000004 (gasCost)
            if (step.gas != prevGas || step.gasCost != prevGasCost) {
                writeGasInfoToRam(memMgr, ramSpace, snapKey, step.gas, step.gasCost);
                prevGas = step.gas;
                prevGasCost = step.gasCost;
            }

            // Manage call stack frames based on depth
            // Only recreate all frames when depth changes; otherwise just update current frame PC
            if (step.depth != lastCallStackDepth) {
                // Depth changed - recreate all frames with correct levels
                updateCallStack(traceStack, depthToFrame, step.depth, snapKey,
                              depthToContract, depthToPC, builder.language);
                lastCallStackDepth = step.depth;
            } else {
                // Depth unchanged - just update current frame (frame 0) PC
                updateCurrentFramePC(traceStack, step.depth, snapKey, currentPc, builder.language);
            }

            // Check for cancellation
            if (monitor.isCancelled()) {
                MothraLog.info(this, "  → Cancelled by user at snapshot " + snapNum);
                throw new CancelledException();
            }

            // Progress indicator with percentage and ETA
            if (i % updateFrequency == 0 || i == steps.size() - 1) {
                double percentage = (snapNum * 100.0) / totalSteps;

                // Calculate ETA
                long elapsedTime = System.currentTimeMillis() - startTime;
                long estimatedTotal = (long) (elapsedTime / (snapNum / (double) totalSteps));
                long remainingTime = estimatedTotal - elapsedTime;
                String eta = formatTime(remainingTime);

                // Update progress bar (42% to 90% range)
                int currentProgress = PROGRESS_START + (int) ((snapNum * PROGRESS_RANGE) / totalSteps);
                monitor.setProgress(currentProgress);
                monitor.setMessage(String.format("Creating snapshot %d/%d (ETA: %s) - %s",
                    snapNum, totalSteps, eta, step.op));

                MothraLog.progress(this, String.format("  → Snapshot %d/%d (%.1f%%) - %s @ PC=0x%x (ETA: %s)",
                    snapNum, totalSteps, percentage, step.op, currentPc, eta));
            }
        }

        MothraLog.info(this, "  ✓ Created " + totalSteps + " instruction snapshots");
    }

    private void setRegister(TraceMemorySpace memSpace,
                             ghidra.program.model.lang.Language lang,
                             long snap, String regName, long value) {
        Register reg = lang.getRegister(regName);
        if (reg == null) return;

        try {
            RegisterValue regValue = new RegisterValue(reg, BigInteger.valueOf(value));
            memSpace.setValue(snap, regValue);
        } catch (Exception e) {
            MothraLog.error(this, "ERROR writing register " + regName + ": " + e.getMessage());
        }
    }

    private void setRegisterBig(TraceMemorySpace memSpace,
                                ghidra.program.model.lang.Language lang,
                                long snap, String regName, BigInteger value) {
        Register reg = lang.getRegister(regName);
        if (reg == null) return;

        try {
            RegisterValue regValue = new RegisterValue(reg, value);
            memSpace.setValue(snap, regValue);
        } catch (Exception e) {
            MothraLog.error(this, "ERROR writing register " + regName + ": " + e.getMessage());
        }
    }

    /**
     * Write stack data to stack memory
     * Each stack item is 32 bytes (256 bits) in EVM
     * Stack space has wordsize=8, so each addressing unit = 8 bytes
     * Each stack item = 32 bytes = 4 addressing units
     */
    private void writeStackToMemory(TraceMemoryManager memMgr,
                                    AddressSpace stkSpace,
                                    long snap,
                                    long prev_sp,
                                    long sp,
                                    List<BigInteger> stack) throws Exception {

        // Clear stack memory between prev_sp and STACK_TOP
        // prev_sp and STACK_TOP are in addressing units (each unit = 8 bytes)
        if (prev_sp < STACK_TOP) {
            Address clearStart = stkSpace.getAddress(prev_sp * 8);
            Address clearEnd = stkSpace.getAddress(STACK_TOP * 8 - 1);

            // Calculate size in bytes: (STACK_TOP - sp) addressing units * 8 bytes/unit
            long clearSize = (STACK_TOP - prev_sp) * 8;
            byte[] zeros = new byte[(int) clearSize];

            memMgr.putBytes(snap, clearStart, ByteBuffer.wrap(zeros));
            memMgr.setState(snap, clearStart, clearEnd, TraceMemoryState.KNOWN);
        }

        if (stack.isEmpty()) {
            return;
        }

        // Write each stack item to memory
        // Stack grows downward, so top of stack is at lowest address
        // sp is in addressing units, each stack item occupies 4 addressing units (32 bytes / 8 bytes per unit)
        for (int i = 0; i < stack.size(); i++) {
            BigInteger value = stack.get(stack.size() - 1 - i);  // Top of stack is at end of list
            long addr = sp * 8 + (i * STACK_ITEM_SIZE);  // Each stack item is 4 addressing units apart

            Address stackAddr = stkSpace.getAddress(addr);

            // Convert BigInteger to 32-byte array (big-endian)
            byte[] valueBytes = value.toByteArray();
            byte[] paddedBytes = new byte[STACK_ITEM_SIZE];

            // Pad with zeros or trim to 32 bytes
            if (valueBytes.length <= STACK_ITEM_SIZE) {
                // Copy to the end of paddedBytes (big-endian)
                System.arraycopy(valueBytes, 0,
                               paddedBytes, STACK_ITEM_SIZE - valueBytes.length,
                               valueBytes.length);
            } else {
                // Take only the last 32 bytes if value is larger
                System.arraycopy(valueBytes, valueBytes.length - STACK_ITEM_SIZE,
                               paddedBytes, 0, STACK_ITEM_SIZE);
            }

            // Write to trace memory
            memMgr.putBytes(snap, stackAddr, ByteBuffer.wrap(paddedBytes));

            // Mark as KNOWN
            Address endAddr = stackAddr.add(STACK_ITEM_SIZE - 1);
            memMgr.setState(snap, stackAddr, endAddr, TraceMemoryState.KNOWN);
        }
    }

    /**
     * Write calldata to RAM at CALLDATA_BASE (0x40000000)
     * Format: length (4 bytes, big-endian) + data
     *
     * @param builder Trace builder
     * @param snap Snapshot key
     * @param callData Call data hex string (with or without 0x prefix)
     */
    private void writeCalldataToMemory(TraceMemoryManager memMgr, AddressSpace ramSpace,
                                       long snap, String callData) throws Exception {
        Address baseAddr = ramSpace.getAddress(CALLDATA_BASE);

        // Convert calldata hex string to bytes
        byte[] dataBytes = hexToBytes(callData);
        int dataLength = dataBytes.length;

        // Create buffer: 4 bytes for length + data bytes
        byte[] buffer = new byte[4 + dataLength];

        // Write length as 4-byte big-endian
        buffer[0] = (byte) ((dataLength >> 24) & 0xFF);
        buffer[1] = (byte) ((dataLength >> 16) & 0xFF);
        buffer[2] = (byte) ((dataLength >> 8) & 0xFF);
        buffer[3] = (byte) (dataLength & 0xFF);

        // Copy data
        System.arraycopy(dataBytes, 0, buffer, 4, dataLength);

        // Write to memory
        memMgr.putBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

        // Mark as KNOWN
        if (buffer.length > 0) {
            Address endAddr = baseAddr.add(buffer.length - 1);
            memMgr.setState(snap, baseAddr, endAddr, TraceMemoryState.KNOWN);
        }
    }

    /**
     * Write EVM memory to RAM at EVM_MEMORY_BASE (0x50000000)
     * Format: length (4 bytes, big-endian) + data
     *
     * @param builder Trace builder
     * @param snap Snapshot key
     * @param evmMemory EVM memory hex string (without 0x prefix)
     */
    private void writeEvmMemoryToRam(TraceMemoryManager memMgr, AddressSpace ramSpace,
                                     long snap, String evmMemory) throws Exception {
        Address baseAddr = ramSpace.getAddress(EVM_MEMORY_BASE);

        // Convert memory hex string to bytes
        byte[] dataBytes = (evmMemory != null && !evmMemory.isEmpty()) ? hexToBytes(evmMemory) : new byte[0];
        int dataLength = dataBytes.length;

        // Debug logging for first few snapshots
        if (snap <= 3) {
            MothraLog.debug(this, "  writeEvmMemoryToRam: snap=" + snap +
                ", evmMemory=" + (evmMemory == null ? "null" : (evmMemory.isEmpty() ? "empty" : evmMemory.length()/2 + " bytes")) +
                ", dataLength=" + dataLength);
        }

        // Create buffer: 4 bytes for length + data bytes
        byte[] buffer = new byte[4 + dataLength];

        // Write length as 4-byte big-endian
        buffer[0] = (byte) ((dataLength >> 24) & 0xFF);
        buffer[1] = (byte) ((dataLength >> 16) & 0xFF);
        buffer[2] = (byte) ((dataLength >> 8) & 0xFF);
        buffer[3] = (byte) (dataLength & 0xFF);

        // Copy data
        if (dataLength > 0) {
            System.arraycopy(dataBytes, 0, buffer, 4, dataLength);
        }

        // Write to memory
        memMgr.putBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

        // Mark as KNOWN
        if (buffer.length > 0) {
            Address endAddr = baseAddr.add(buffer.length - 1);
            memMgr.setState(snap, baseAddr, endAddr, TraceMemoryState.KNOWN);
        }
    }

    /**
     * Write EVM stack data to RAM at EVM_STACK_BASE (0x60000000)
     * Format: length (4 bytes, big-endian, number of stack items) + data (each item 32 bytes)
     *
     * @param builder Trace builder
     * @param snap Snapshot key
     * @param evmStack List of stack values (hex strings, top of stack at end of list)
     */
    private void writeEvmStackToRam(TraceMemoryManager memMgr, AddressSpace ramSpace,
                                    long snap, List<String> evmStack) throws Exception {
        Address baseAddr = ramSpace.getAddress(EVM_STACK_BASE);

        int stackSize = (evmStack != null) ? evmStack.size() : 0;

        // Create buffer: 4 bytes for length + stackSize * 32 bytes for data
        byte[] buffer = new byte[4 + stackSize * STACK_ITEM_SIZE];

        // Write length (number of stack items) as 4-byte big-endian
        buffer[0] = (byte) ((stackSize >> 24) & 0xFF);
        buffer[1] = (byte) ((stackSize >> 16) & 0xFF);
        buffer[2] = (byte) ((stackSize >> 8) & 0xFF);
        buffer[3] = (byte) (stackSize & 0xFF);

        // Write each stack item (32 bytes each, big-endian)
        if (evmStack != null) {
            for (int i = 0; i < evmStack.size(); i++) {
                BigInteger value = hexToBigInteger(evmStack.get(i));
                byte[] valueBytes = value.toByteArray();
                byte[] paddedBytes = new byte[STACK_ITEM_SIZE];

                // Pad with zeros or trim to 32 bytes
                if (valueBytes.length <= STACK_ITEM_SIZE) {
                    System.arraycopy(valueBytes, 0,
                                   paddedBytes, STACK_ITEM_SIZE - valueBytes.length,
                                   valueBytes.length);
                } else {
                    System.arraycopy(valueBytes, valueBytes.length - STACK_ITEM_SIZE,
                                   paddedBytes, 0, STACK_ITEM_SIZE);
                }

                // Copy to buffer at offset 4 + i * 32
                System.arraycopy(paddedBytes, 0, buffer, 4 + i * STACK_ITEM_SIZE, STACK_ITEM_SIZE);
            }
        }

        // Write to memory
        memMgr.putBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

        // Mark as KNOWN
        if (buffer.length > 0) {
            Address endAddr = baseAddr.add(buffer.length - 1);
            memMgr.setState(snap, baseAddr, endAddr, TraceMemoryState.KNOWN);
        }
    }

    /**
     * Write storage to RAM at STORAGE_BASE (0x70000000)
     * Format: length (4 bytes, big-endian, number of key-value pairs) + key1 (32 bytes) + value1 (32 bytes) + ...
     *
     * @param builder Trace builder
     * @param snap Snapshot key
     * @param storage Map of storage key -> value (hex strings)
     */
    private void writeStorageToRam(TraceMemoryManager memMgr, AddressSpace ramSpace,
                                   long snap, Map<String, String> storage) throws Exception {
        Address baseAddr = ramSpace.getAddress(STORAGE_BASE);

        int pairCount = (storage != null) ? storage.size() : 0;

        // Create buffer: 4 bytes for length + pairCount * 64 bytes (32 for key + 32 for value)
        byte[] buffer = new byte[4 + pairCount * 64];

        // Write length (number of key-value pairs) as 4-byte big-endian
        buffer[0] = (byte) ((pairCount >> 24) & 0xFF);
        buffer[1] = (byte) ((pairCount >> 16) & 0xFF);
        buffer[2] = (byte) ((pairCount >> 8) & 0xFF);
        buffer[3] = (byte) (pairCount & 0xFF);

        // Write each key-value pair (32 bytes each)
        if (storage != null) {
            int index = 0;
            for (Map.Entry<String, String> entry : storage.entrySet()) {
                // Write key (32 bytes)
                BigInteger keyValue = hexToBigInteger(entry.getKey());
                byte[] keyBytes = keyValue.toByteArray();
                byte[] paddedKey = new byte[STACK_ITEM_SIZE];
                if (keyBytes.length <= STACK_ITEM_SIZE) {
                    System.arraycopy(keyBytes, 0,
                                   paddedKey, STACK_ITEM_SIZE - keyBytes.length,
                                   keyBytes.length);
                } else {
                    System.arraycopy(keyBytes, keyBytes.length - STACK_ITEM_SIZE,
                                   paddedKey, 0, STACK_ITEM_SIZE);
                }
                System.arraycopy(paddedKey, 0, buffer, 4 + index * 64, STACK_ITEM_SIZE);

                // Write value (32 bytes)
                BigInteger valValue = hexToBigInteger(entry.getValue());
                byte[] valBytes = valValue.toByteArray();
                byte[] paddedVal = new byte[STACK_ITEM_SIZE];
                if (valBytes.length <= STACK_ITEM_SIZE) {
                    System.arraycopy(valBytes, 0,
                                   paddedVal, STACK_ITEM_SIZE - valBytes.length,
                                   valBytes.length);
                } else {
                    System.arraycopy(valBytes, valBytes.length - STACK_ITEM_SIZE,
                                   paddedVal, 0, STACK_ITEM_SIZE);
                }
                System.arraycopy(paddedVal, 0, buffer, 4 + index * 64 + STACK_ITEM_SIZE, STACK_ITEM_SIZE);

                index++;
            }
        }

        // Write to memory
        memMgr.putBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

        // Mark as KNOWN
        if (buffer.length > 0) {
            Address endAddr = baseAddr.add(buffer.length - 1);
            memMgr.setState(snap, baseAddr, endAddr, TraceMemoryState.KNOWN);
        }
    }

    /**
     * Write gas information to RAM at GAS_BASE (0x80000000)
     * Format:
     * - 0x80000000: gas (4 bytes, big-endian)
     * - 0x80000004: gasCost (4 bytes, big-endian)
     *
     * @param builder Trace builder
     * @param snap Snapshot key
     * @param gas Gas remaining
     * @param gasCost Gas cost of current operation
     */
    private void writeGasInfoToRam(TraceMemoryManager memMgr, AddressSpace ramSpace,
                                   long snap, long gas, long gasCost) throws Exception {
        Address baseAddr = ramSpace.getAddress(GAS_BASE);

        // Create buffer: 4 bytes for gas + 4 bytes for gasCost
        byte[] buffer = new byte[8];

        // Write gas as 4-byte big-endian (truncate to 32-bit)
        int gasInt = (int) gas;  // EVM gas fits in 32 bits
        buffer[0] = (byte) ((gasInt >> 24) & 0xFF);
        buffer[1] = (byte) ((gasInt >> 16) & 0xFF);
        buffer[2] = (byte) ((gasInt >> 8) & 0xFF);
        buffer[3] = (byte) (gasInt & 0xFF);

        // Write gasCost as 4-byte big-endian (truncate to 32-bit)
        int gasCostInt = (int) gasCost;
        buffer[4] = (byte) ((gasCostInt >> 24) & 0xFF);
        buffer[5] = (byte) ((gasCostInt >> 16) & 0xFF);
        buffer[6] = (byte) ((gasCostInt >> 8) & 0xFF);
        buffer[7] = (byte) (gasCostInt & 0xFF);

        // Write to memory
        memMgr.putBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

        // Mark as KNOWN
        Address endAddr = baseAddr.add(7);
        memMgr.setState(snap, baseAddr, endAddr, TraceMemoryState.KNOWN);
    }

    /**
     * Convert hex string to byte array
     */
    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }

        // Remove 0x prefix if present
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }

        if (hex.isEmpty()) {
            return new byte[0];
        }

        // Handle odd length
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private void printTraceSummary(ToyDBTraceBuilder builder) {
        var timeManager = builder.trace.getTimeManager();
        var memMgr = builder.trace.getMemoryManager();
        var threadMgr = builder.trace.getThreadManager();

        MothraLog.info(this, "  Snapshots:      " + timeManager.getSnapshotCount());
        MothraLog.info(this, "  Memory Regions: " + memMgr.getAllRegions().size());
        MothraLog.info(this, "  Threads:        " + threadMgr.getAllThreads().size());
    }

    private void saveTraceToPacked(ToyDBTraceBuilder builder, String traceName,
                                   String outputFile) throws Exception {
        File output = new File(outputFile);
        if (output.exists()) {
            output.delete();
        }

        // saveToPackedFile() flushes the object value write-behind cache
        // (objectManager.flushWbCaches()) before packing. This is critical —
        // without the flush, all object model data (threads, memory regions,
        // attributes) stays in the cache and is lost in the packed file.
        //
        // The R-tree overflow ClassCastException is mitigated by using
        // Lifespan.at() instead of Lifespan.nowOn() for per-snapshot
        // attributes. If it still occurs (e.g., during delete-and-regenerate),
        // fall back to direct database packing — the flush will have already
        // completed before the exception point in most cases.
        try {
            builder.trace.saveToPackedFile(output, TaskMonitor.DUMMY);
        } catch (Exception e) {
            MothraLog.warn(this, "saveToPackedFile failed (" + e.getClass().getSimpleName()
                    + ": " + e.getMessage() + "), retrying with direct pack...");
            if (output.exists()) {
                output.delete();
            }
            try {
                db.DBHandle dbh = builder.trace.getDBHandle();
                ghidra.framework.store.db.PackedDatabase.packDatabase(
                        dbh, traceName, "Trace", output, TaskMonitor.DUMMY);
            } catch (Exception fallbackEx) {
                MothraLog.error(this, "Direct pack also failed: " + fallbackEx.getMessage());
                throw fallbackEx;
            }
        }

        MothraLog.info(this, "  ✓ Saved to: " + outputFile);
    }

    /**
     * Parse hex string to BigInteger
     */
    private BigInteger hexToBigInteger(String hex) {
        if (hex == null || hex.isEmpty()) {
            return BigInteger.ZERO;
        }

        // Remove 0x prefix if present
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            hex = hex.substring(2);
        }

        if (hex.isEmpty()) {
            return BigInteger.ZERO;
        }

        return new BigInteger(hex, 16);
    }

    /**
     * Update current frame's PC and ensure all parent frames exist.
     *
     * Ghidra's trace stack model requires frames to be explicitly present at
     * each snapshot — they don't persist automatically across snapshots.
     * All frames must be created via getFrame() at every snapshot for the
     * stack window to display them.
     *
     * Only frame 0's PC is written per snapshot (with Lifespan.at to avoid
     * overlapping R-tree entries). Parent frame PCs persist from the last
     * updateCallStack() call via Lifespan.nowOn.
     *
     * @param traceStack TraceStack to update
     * @param currentDepth Current call depth
     * @param snapKey Snapshot key
     * @param currentPc Current program counter
     * @param language Ghidra language
     */
    private void updateCurrentFramePC(TraceStack traceStack,
                                      int currentDepth,
                                      long snapKey,
                                      long currentPc,
                                      ghidra.program.model.lang.Language language) {
        try {
            AddressSpace ramSpace = language.getAddressFactory().getAddressSpace("ram");

            // Ensure ALL frames exist at this snapshot so the stack window
            // displays the full call hierarchy.
            for (int depth = 1; depth <= currentDepth; depth++) {
                int frameLevel = currentDepth - depth;
                TraceStackFrame frame = traceStack.getFrame(snapKey, frameLevel, true);

                // Only write PC for frame 0 (current frame) — parent frame
                // PCs persist from updateCallStack() via Lifespan.nowOn().
                // Using Lifespan.at() for frame 0 avoids accumulating
                // overlapping entries in the R-tree spatial index.
                if (depth == currentDepth) {
                    Address pcAddr = ramSpace.getAddress(currentPc);
                    frame.setProgramCounter(Lifespan.at(snapKey), pcAddr);
                }
            }

        } catch (Exception e) {
            MothraLog.error(this, "Error updating current frame PC: " + e.getMessage(), e);
        }
    }

    /**
     * Update call stack based on current execution depth
     *
     * Creates frames with inverted levels so Frame 0 is always the currently executing frame.
     * Standard debugger convention: Frame 0 = innermost (current), higher frames = callers.
     *
     * Called ONLY when depth changes, not at every snapshot.
     *
     * @param traceStack TraceStack to update
     * @param depthToFrame Map tracking frames by depth
     * @param currentDepth Current call depth
     * @param snapKey Snapshot key
     * @param depthToContract Map of depth to contract address
     * @param depthToPC Map of depth to program counter
     * @param language Ghidra language
     */
    private void updateCallStack(TraceStack traceStack,
                                Map<Integer, TraceStackFrame> depthToFrame,
                                int currentDepth,
                                long snapKey,
                                Map<Integer, String> depthToContract,
                                Map<Integer, Long> depthToPC,
                                ghidra.program.model.lang.Language language) {
        try {
            AddressSpace ramSpace = language.getAddressFactory().getAddressSpace("ram");

            // Clear frame tracking - we'll recreate with correct levels
            depthToFrame.clear();

            // Create frames for ALL depths with inverted levels
            // Formula: frameLevel = currentDepth - depth
            // This ensures frame 0 is always the currently executing frame
            for (int depth = 1; depth <= currentDepth; depth++) {
                // Calculate inverted frame level: current depth = frame 0
                int frameLevel = currentDepth - depth;

                String contract = depthToContract.getOrDefault(depth, "0x?");
                Long pc = depthToPC.getOrDefault(depth, 0L);

                String frameName = "Contract_" + contract + "_depth_" + depth;

                // Create frame at correct level
                TraceStackFrame frame = traceStack.getFrame(snapKey, frameLevel, true);

                // Set PC for this frame. Use Lifespan.nowOn() so parent frame PCs
                // persist to subsequent snapshots (visible in the stack window
                // without re-creation at every snapshot). This is safe because
                // updateCallStack only runs on depth changes (infrequent), so
                // the number of overlapping nowOn entries stays small.
                Address pcAddr = ramSpace.getAddress(pc);
                frame.setProgramCounter(Lifespan.nowOn(snapKey), pcAddr);

                // Set frame comment/name
                frame.setComment(snapKey, frameName);

                // Track frame by depth
                depthToFrame.put(depth, frame);
            }

            // Log summary of call stack update (not every frame)
            MothraLog.debug(this, "  → Updated call stack: " + currentDepth + " frame(s) " +
                          "(frame 0 = depth " + currentDepth + ")");

        } catch (Exception e) {
            MothraLog.error(this, "Error updating call stack: " + e.getMessage(), e);
        }
    }

    /**
     * Update program counter in trace object model
     *
     * This updates the _pc attribute on the thread object, which is used by
     * the "Track program counter" mode in Ghidra's debugger. This is separate
     * from the PC register value in register memory space.
     *
     * The _pc attribute must be set as an Address object (not a primitive long)
     * for Ghidra's Time window to correctly display the PC column.
     *
     * @param thread TraceThread to update
     * @param snapKey Snapshot key
     * @param pcValue Program counter value
     * @param language Ghidra language for address conversion
     */
    private void updateProgramCounterInObjectModel(TraceThread thread, long snapKey, long pcValue,
                                                   ghidra.program.model.lang.Language language) {
        try {
            TraceObject threadObj = thread.getObject();
            if (threadObj != null) {
                // Convert long PC to Address object for Time window display
                AddressSpace ramSpace = language.getAddressFactory().getAddressSpace("ram");
                Address pcAddr = ramSpace.getAddress(pcValue);

                // Set _pc attribute for "Track program counter" mode.
                // Use Lifespan.at() (single-point lifespan) instead of nowOn()
                // to avoid accumulating overlapping R-tree entries in the
                // DBTraceObjectValueWriteBehindCache, which triggers a
                // ClassCastException in Ghidra's R-tree overflow handling.
                threadObj.setAttribute(Lifespan.at(snapKey), "_pc", pcAddr);
            }
        } catch (Exception e) {
            MothraLog.error(this, "Error updating PC in object model: " + e.getMessage(), e);
        }
    }

    /**
     * Format time in milliseconds to human-readable string
     * @param millis Time in milliseconds
     * @return Formatted string (e.g., "2m 30s", "45s", "1h 15m")
     */
    private String formatTime(long millis) {
        if (millis < 0) {
            return "calculating...";
        }

        long seconds = millis / 1000;

        if (seconds < 60) {
            return seconds + "s";
        }

        long minutes = seconds / 60;
        long remainingSeconds = seconds % 60;

        if (minutes < 60) {
            if (remainingSeconds > 0) {
                return minutes + "m " + remainingSeconds + "s";
            }
            return minutes + "m";
        }

        long hours = minutes / 60;
        long remainingMinutes = minutes % 60;

        if (remainingMinutes > 0) {
            return hours + "h " + remainingMinutes + "m";
        }
        return hours + "h";
    }
}
