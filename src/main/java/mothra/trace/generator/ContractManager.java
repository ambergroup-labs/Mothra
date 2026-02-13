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

import java.io.IOException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.*;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Instruction;
import ghidra.trace.model.Lifespan;

import mothra.trace.builder.ToyDBTraceBuilder;
import mothra.trace.data.DataStore;
import mothra.util.MothraLog;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceModule;
import ghidra.trace.model.modules.TraceStaticMappingManager;
import ghidra.util.task.TaskMonitor;

/**
 * ContractManager - Manages contract bytecode deployment in trace database
 *
 * Responsibilities:
 * - Track which contract is active at each call depth
 * - Deploy contract bytecode to code memory when depth changes
 * - Manage contract address to bytecode mappings
 */
public class ContractManager {

    private final ToyDBTraceBuilder builder;
    private final DataStore dataStore;

    // Call sequence from trace analysis (contains address and call data)
    private final List<DataStore.ContractCall> callSequence;
    private int callSequenceIndex;

    // Current contract being executed
    private String currentContract;
    private Long currentCodeAddress;
    private String currentCallData;

    // Map of contract address to its code space address
    private final Map<String, Long> contractToCodeAddress;

    // Map of contract address to its module
    private final Map<String, TraceModule> contractToModule;

    // Maximum code size for EVM (EIP-170: 24KB)
    private static final long MAX_CODE_SIZE = 0x6000;

    // Code address offset for each contract (64KB per contract)
    private static final long CODE_ADDRESS_OFFSET = 0x10000L;

    /**
     * Create a new ContractManager
     *
     * @param builder Trace builder
     * @param dataStore DataStore containing all contract data
     */
    public ContractManager(ToyDBTraceBuilder builder, DataStore dataStore) {
        this.builder = builder;
        this.dataStore = dataStore;
        this.callSequence = dataStore.getContractExecutionSequence();
        this.callSequenceIndex = 0;
        this.currentContract = null;
        this.currentCodeAddress = 0L;
        this.currentCallData = null;
        this.contractToCodeAddress = new HashMap<>();
        this.contractToModule = new HashMap<>();
    }

    /**
     * Get bytecode for a contract address from DataStore
     */
    public byte[] getBytecode(String address) {
        String normalizedAddr = normalizeAddress(address);
        String hexBytecode = dataStore.getContractBytecode().get(normalizedAddr);

        if (hexBytecode == null || hexBytecode.isEmpty()) {
            return null;
        }

        // Convert hex string to bytes
        return hexToBytes(hexBytecode);
    }

    /**
     * Advance to next contract in the call sequence
     * This should be called when depth changes during instruction processing.
     * Since all contracts are already deployed, this just updates the active contract.
     *
     * @param snap Current snapshot number
     * @return The TraceModule if contract was changed, null otherwise
     */
    public TraceModule advanceToNextContract(long snap) throws Exception {
        // Check if we have more contracts in sequence
        if (callSequenceIndex >= callSequence.size()) {
            return null;
        }

        // Get next contract from call sequence
        DataStore.ContractCall nextCall = callSequence.get(callSequenceIndex);
        String newContract = normalizeAddress(nextCall.address);
        String newCallData = nextCall.callData;
        callSequenceIndex++;

        // Always update call data (even if contract doesn't change)
        currentCallData = newCallData;

        // Check if contract is actually changing
        if (newContract.equals(currentContract)) {
            return null;  // Same contract, no module update needed
        }

        // Update current contract
        currentContract = newContract;
        currentCodeAddress = contractToCodeAddress.get(newContract);
        if (currentCodeAddress == null) {
            currentCodeAddress = 0L;
        }

        // Get the already-deployed module for this contract
        TraceModule module = contractToModule.get(newContract);
        if (module == null) {
            MothraLog.warn(this, "  ⚠ Module not found for contract: " + newContract);
            return null;
        }

        return module;
    }

    /**
     * Deploy contract bytecode to code memory, disassemble it, and create module
     *
     * @param address Contract address
     * @param snap Snapshot number
     * @param codeAddress Address in code space where contract should be deployed
     * @return The created TraceModule
     */
    private TraceModule deployContract(String address, long snap, long codeAddress) throws Exception {
        String normalizedAddr = normalizeAddress(address);
        byte[] bytecode = getBytecode(normalizedAddr);

        if (bytecode == null) {
            throw new Exception("Bytecode not found for address: " + address);
        }

        MothraLog.info(this, "  → Deploying contract " + normalizedAddr +
                         " to code[0x" + Long.toHexString(codeAddress) + "] (" +
                         bytecode.length + " bytes)");

        // Get code memory manager
        TraceMemoryManager memMgr = builder.trace.getMemoryManager();

        // Get code address space
        AddressSpace codeSpace = builder.language.getAddressFactory().getAddressSpace("ram");
        if (codeSpace == null) {
            throw new Exception("Code address space not found");
        }

        // Deploy contract at specified code address
        Address startAddr = codeSpace.getAddress(codeAddress);

        // Write bytecode to code memory
        memMgr.putBytes(snap, startAddr, ByteBuffer.wrap(bytecode));

        // Mark memory as KNOWN for the bytecode region
        Address bytecodeEnd = startAddr.add(bytecode.length - 1);
        memMgr.setState(snap, startAddr, bytecodeEnd, TraceMemoryState.KNOWN);

        MothraLog.info(this, "  ✓ Contract deployed to code[0x" + Long.toHexString(codeAddress) +
                         ":0x" + Long.toHexString(codeAddress + bytecode.length - 1) + "]");

        // Disassemble the bytecode
        MothraLog.info(this, "  → Disassembling bytecode...");
        disassembleBytecode(snap, startAddr, bytecode.length);

        // Create module for this contract
        MothraLog.info(this, "  → Creating module for contract...");
        TraceModule module = createModuleForContract(normalizedAddr, snap, codeAddress, bytecode.length);

        // Store the mapping
        contractToCodeAddress.put(normalizedAddr, codeAddress);
        contractToModule.put(normalizedAddr, module);

        return module;
    }

    /**
     * Create a module for a contract
     *
     * @param address Contract address (normalized)
     * @param snap Snapshot number
     * @param codeAddress Address in code space where contract is deployed
     * @param length Length of contract bytecode
     * @return The created TraceModule
     */
    private TraceModule createModuleForContract(String address, long snap, long codeAddress, int length) throws Exception {
        var modMgr = builder.trace.getModuleManager();

        // Get code address space
        AddressSpace codeSpace = builder.language.getAddressFactory().getAddressSpace("ram");
        if (codeSpace == null) {
            throw new Exception("Code address space not found");
        }

        // Create address range for the module (actual contract size)
        Address startAddr = codeSpace.getAddress(codeAddress);
        Address endAddr = codeSpace.getAddress(codeAddress + length - 1);
        AddressRange range = new AddressRangeImpl(startAddr, endAddr);

        // Create lifespan for all time (since all contracts deployed at start)
        Lifespan lifespan = Lifespan.ALL;

        // Module name is the contract address
        String moduleName = "0x" + address;

        // Create unique path for module
        String modulePath = "Modules[" + moduleName + "]";

        try {
            TraceModule module = modMgr.addModule(modulePath, moduleName, range, lifespan);
            MothraLog.info(this, "  ✓ Module created: " + moduleName +
                             " [code:0x" + Long.toHexString(codeAddress) + "-0x" +
                             Long.toHexString(codeAddress + length - 1) + "]");
            return module;
        } catch (Exception e) {
            MothraLog.error(this, "  ⚠ Module creation failed: " + e.getMessage());
            throw e;
        }
    }

    /**
     * Disassemble bytecode in code memory
     *
     * @param snap Snapshot number
     * @param startAddr Start address of bytecode
     * @param length Length of bytecode in bytes
     */
    private void disassembleBytecode(long snap, Address startAddr, int length) {
        try {
            // Use the trace's program view for disassembly
            var programView = builder.trace.getProgramView();

            // Create a disassembler for the current language
            Disassembler disassembler = Disassembler.getDisassembler(
                programView, TaskMonitor.DUMMY, null);

            // Calculate end address
            Address endAddr = startAddr.add(length - 1);

            // Disassemble the bytecode region
            var addressSet = builder.trace.getBaseAddressFactory()
                .getAddressSet(startAddr, endAddr);

            disassembler.disassemble(startAddr, addressSet, true);

            MothraLog.info(this, "  ✓ Disassembled " + length + " bytes");

        } catch (Exception e) {
            MothraLog.error(this, "  ⚠ Disassembly failed: " + e.getMessage());
            // Don't throw - bytecode is still deployed even if disassembly fails
        }
    }

    /**
     * Get current contract address
     */
    public String getCurrentContract() {
        return currentContract;
    }

    /**
     * Get current contract's code address
     */
    public Long getCurrentCodeAddress() {
        return currentCodeAddress;
    }

    /**
     * Get current call data (input data for the current contract call)
     * @return Call data hex string (with 0x prefix), or null if not available
     */
    public String getCurrentCallData() {
        return currentCallData;
    }

    /**
     * Get all contract addresses
     */
    public Set<String> getAllContracts() {
        return new HashSet<>(dataStore.getContractList());
    }

    /**
     * Deploy all contracts at initialization
     * Each contract is deployed at a different offset in code space:
     * - Contract 0: 0x00000
     * - Contract 1: 0x10000
     * - Contract 2: 0x20000
     * - etc.
     *
     * @param snap Snapshot number
     * @return List of created TraceModules
     */
    public List<TraceModule> deployAllContracts(long snap) throws Exception {
        // Get unique contracts from DataStore (already filtered and ordered)
        List<String> uniqueContracts = dataStore.getContractList();

        if (uniqueContracts.isEmpty()) {
            throw new Exception("No contracts to deploy");
        }

        List<TraceModule> modules = new ArrayList<>();
        MothraLog.progress(this, "  → Deploying " + uniqueContracts.size() + " unique contracts...");

        // Deploy each contract at its own code address using deployment addresses from DataStore
        Map<String, Long> deploymentAddresses = dataStore.getContractDeploymentAddresses();
        for (String contract : uniqueContracts) {
            Long codeAddress = deploymentAddresses.get(contract);
            if (codeAddress == null) {
                MothraLog.warn(this, "  ⚠ No deployment address for contract: " + contract);
                continue;
            }

            TraceModule module = deployContract(contract, snap, codeAddress);
            modules.add(module);
        }

        // Initialize first contract as active
        if (!callSequence.isEmpty()) {
            DataStore.ContractCall firstCall = callSequence.get(0);
            currentContract = normalizeAddress(firstCall.address);
            currentCallData = firstCall.callData;
            currentCodeAddress = contractToCodeAddress.get(currentContract);
            if (currentCodeAddress == null) {
                currentCodeAddress = 0L;
            }
            callSequenceIndex = 1;  // Start from next contract in sequence
        }

        MothraLog.info(this, "  ✓ All contracts deployed");
        return modules;
    }


    /**
     * Normalize address (lowercase, remove 0x prefix)
     */
    private String normalizeAddress(String address) {
        String normalized = address.toLowerCase();
        if (normalized.startsWith("0x")) {
            normalized = normalized.substring(2);
        }
        return normalized;
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

        // Handle odd length
        if (hex.length() % 2 != 0) {
            hex = "0" + hex;
        }

        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    /**
     * Get code address for a contract
     *
     * @param address Contract address
     * @return Code address, or null if contract not deployed
     */
    public Long getCodeAddressForContract(String address) {
        return contractToCodeAddress.get(normalizeAddress(address));
    }

    /**
     * Get module for a contract
     *
     * @param address Contract address
     * @return TraceModule, or null if contract not deployed
     */
    public TraceModule getModuleForContract(String address) {
        return contractToModule.get(normalizeAddress(address));
    }

    /**
     * Get all deployed modules
     *
     * @return List of all modules
     */
    public List<TraceModule> getAllModules() {
        return new ArrayList<>(contractToModule.values());
    }

    /**
     * Create static mappings to a single program database containing all contracts
     * Maps each TraceModule to the corresponding memory region in the program database.
     *
     * Since both trace DB and program DB use the same deployment addresses from DataStore,
     * the mapping is straightforward: trace ram:ADDRESS → program ram:ADDRESS
     *
     * @param project Ghidra project
     * @param programName Name of the program database (e.g., "EthTx_abc123.evm")
     * @return Number of mappings created
     */
    public int createStaticMappingsToProgram(Project project, String programName) {
        if (project == null) {
            MothraLog.warn(this, "  ⚠ No project available, skipping static mappings");
            return 0;
        }

        if (programName == null || programName.isEmpty()) {
            MothraLog.warn(this, "  ⚠ No program name provided, skipping static mappings");
            return 0;
        }

        // Find the program database in the project
        DomainFile programFile = findProgramInProject(project, programName);
        if (programFile == null) {
            MothraLog.warn(this, "  ⚠ Program not found: " + programName + ", skipping static mappings");
            return 0;
        }

        // Get program URL
        URL programURL;
        try {
            programURL = programFile.getLocalProjectURL(null);
            if (programURL == null) {
                programURL = programFile.getSharedProjectURL(null);
            }
            if (programURL == null) {
                MothraLog.error(this, "  ⚠ Could not get URL for program: " + programName);
                return 0;
            }
        } catch (Exception e) {
            MothraLog.error(this, "  ⚠ Error getting program URL: " + e.getMessage());
            return 0;
        }

        TraceStaticMappingManager mappingMgr = builder.trace.getStaticMappingManager();
        int mappingCount = 0;

        MothraLog.info(this, "  → Creating static mappings to program: " + programName);

        for (Map.Entry<String, TraceModule> entry : contractToModule.entrySet()) {
            String contractAddr = entry.getKey();
            TraceModule module = entry.getValue();
            Long codeAddress = contractToCodeAddress.get(contractAddr);

            if (codeAddress == null) {
                MothraLog.warn(this, "    ⚠ No code address for contract: 0x" + contractAddr);
                continue;
            }

            try {
                // Get bytecode to determine range
                byte[] bytecode = getBytecode(contractAddr);
                if (bytecode == null || bytecode.length == 0) {
                    MothraLog.warn(this, "    ⚠ No bytecode for contract: 0x" + contractAddr);
                    continue;
                }

                // Create address range in trace database (ram space)
                AddressSpace ramSpace = builder.language.getAddressFactory().getAddressSpace("ram");
                Address traceStartAddr = ramSpace.getAddress(codeAddress);
                Address traceEndAddr = ramSpace.getAddress(codeAddress + bytecode.length - 1);
                AddressRange traceRange = new AddressRangeImpl(traceStartAddr, traceEndAddr);

                // Map to same address in program database
                // Format: "ram:HEXADDRESS" (e.g., "ram:00010000")
                String programAddrStr = String.format("ram:%08x", codeAddress);

                // Create the static mapping
                mappingMgr.add(traceRange, Lifespan.ALL, programURL, programAddrStr);

                MothraLog.info(this, "    ✓ Mapped 0x" + contractAddr +
                                 " [ram:0x" + Long.toHexString(codeAddress) +
                                 ":0x" + Long.toHexString(codeAddress + bytecode.length - 1) + "]" +
                                 " → program " + programAddrStr);
                mappingCount++;

            } catch (Exception e) {
                MothraLog.error(this, "    ⚠ Failed to create mapping for 0x" + contractAddr +
                                 ": " + e.getMessage());
            }
        }

        if (mappingCount > 0) {
            MothraLog.info(this, "  ✓ Created " + mappingCount + " static mapping(s)");
        } else {
            MothraLog.warn(this, "  ⚠ No static mappings created");
        }

        return mappingCount;
    }

    /**
     * Find a program file in the project by name
     *
     * @param project Ghidra project
     * @param programName Name of program to find (e.g., "0xdac17f958d2ee523a2206206994597c13d831ec7.evm")
     * @return DomainFile if found, null otherwise
     */
    private DomainFile findProgramInProject(Project project, String programName) {
        try {
            DomainFolder rootFolder = project.getProjectData().getRootFolder();
            return findProgramRecursive(rootFolder, programName);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Recursively search for a program file by name
     */
    private DomainFile findProgramRecursive(DomainFolder folder, String programName) {
        try {
            // Check files in current folder
            for (DomainFile file : folder.getFiles()) {
                if (file.getName().equals(programName) &&
                    "Program".equals(file.getContentType())) {
                    return file;
                }
            }

            // Search subfolders
            for (DomainFolder subfolder : folder.getFolders()) {
                DomainFile result = findProgramRecursive(subfolder, programName);
                if (result != null) {
                    return result;
                }
            }
        } catch (Exception e) {
            // Ignore errors during search
        }

        return null;
    }

    /**
     * Reset call sequence index (for reprocessing)
     */
    public void resetCallSequence() {
        callSequenceIndex = 0;
        currentContract = null;
        currentCodeAddress = 0L;
        currentCallData = null;
    }
}
