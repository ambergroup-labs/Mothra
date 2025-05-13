package mothra;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMDisassembleAnalyzer extends AbstractAnalyzer {
    private static final String EVM_PROCESSOR = "EVM";
    private static final String EOF_PROCESSOR = "EOF";
    private static final String CODE_BLOCK_NAME = "code";

    public EVMDisassembleAnalyzer() {
        super("EVM Disassembler", "Disassemble EVM bytecode", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        Processor processor = program.getLanguage().getProcessor();
        return isProcessorSupported(processor);
    }

    private boolean isProcessorSupported(Processor processor) {
        return processor.equals(Processor.findOrPossiblyCreateProcessor(EVM_PROCESSOR)) ||
            processor.equals(Processor.findOrPossiblyCreateProcessor(EOF_PROCESSOR));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        AddressSet disSet = createDisassemblySet(program, set);
        disassembleProgram(program, monitor, disSet);
        processPushInstructions(program, set, log);
        processJumpTable(program, set, log);
        return true;
    }

    private AddressSet createDisassemblySet(Program program, AddressSetView set) {
        AddressSet disSet = new AddressSet();
        if (isEOFProcessor(program)) {
            addExecutableBlocks(program, disSet);
        }
        else {
            addCodeBlock(program, set, disSet);
        }
        return disSet;
    }

    private boolean isEOFProcessor(Program program) {
        return program.getLanguage()
                .getProcessor()
                .equals(
                    Processor.findOrPossiblyCreateProcessor(EOF_PROCESSOR));
    }

    private void addExecutableBlocks(Program program, AddressSet disSet) {
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        for (MemoryBlock block : blocks) {
            if (block.isExecute()) {
                disSet.add(block.getStart(), block.getEnd());
            }
        }
    }

    private void addCodeBlock(Program program, AddressSetView set, AddressSet disSet) {
        MemoryBlock code = program.getMemory().getBlock(CODE_BLOCK_NAME);
        if (code != null) {
            AddressSet intersection = set.intersect(new AddressSet(code.getStart(), code.getEnd()));
            disSet.add(intersection);
        }
    }

    private void disassembleProgram(Program program, TaskMonitor monitor, AddressSet disSet) {
        DisassembleCommand cmd = new DisassembleCommand(disSet, null, false);
        cmd.applyTo(program, monitor);
    }

    private void processPushInstructions(Program program, AddressSetView set, MessageLog log) {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);
        while (instIter.hasNext()) {
            Instruction instr = instIter.next();
            processSinglePushInstruction(program, instr, log);
        }
    }

    private void processSinglePushInstruction(Program program, Instruction instr, MessageLog log) {
        String instrMnemonic = instr.getMnemonicString();
        if (instrMnemonic.startsWith("PUSH")) {
            int value = extractMnemonicSuffix(instrMnemonic, "PUSH");
            if (value > 8) {
                try {
                    Address valueStartAddress = instr.getAddress().add(1);
                    byte[] actualValueInBytes = new byte[value];
                    program.getMemory().getBytes(valueStartAddress, actualValueInBytes);
                    String actualValueInHex = bytesToHex(actualValueInBytes);
                    FlatProgramAPI flatAPI = new FlatProgramAPI(program);
                    flatAPI.setPreComment(instr.getAddress(), actualValueInHex);
                }
                catch (Exception e) {
                    log.appendException(e);
                }
            }
        }
    }

    private void processJumpTable(Program program, AddressSetView set, MessageLog log) {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);
        while (instIter.hasNext()) {
            Instruction instr = instIter.next();
            processSingleJumpTableInstruction(program, instr, log);
        }
    }

    private void processSingleJumpTableInstruction(Program program, Instruction instr,
            MessageLog log) {
        String instrMnemonic = instr.getMnemonicString();
        if (!instrMnemonic.startsWith("RJUMPV")) {
            return;
        }

        try {
            // Get immediate value and max index
            int maxIndex = getMaxIndex(program, instr);
            
            // Setup addresses and APIs
            Address jumpTableAddress = instr.getAddress().add(2);
            Address endAddress = jumpTableAddress.add((maxIndex + 1) * 2);
            FlatProgramAPI flatAPI = new FlatProgramAPI(program);
            ReferenceManager refManager = program.getReferenceManager();

            // Initialize jump table
            initializeJumpTable(program, instr, endAddress, flatAPI, refManager, maxIndex);
            
            // Process entries
            processJumpTableEntries(program, instr, jumpTableAddress, endAddress, 
                flatAPI, refManager, maxIndex, log);
        }
        catch (Exception e) {
            log.appendException(e);
        }
    }

    private int getMaxIndex(Program program, Instruction instr) throws Exception {
        Address immediateValueAddress = instr.getAddress().add(1);
        byte[] immediateValueBytes = new byte[1];
        program.getMemory().getBytes(immediateValueAddress, immediateValueBytes);
        String immediateValueInHex = bytesToHex(immediateValueBytes);
        return Integer.parseInt(immediateValueInHex.substring(2), 16);
    }

    private void initializeJumpTable(Program program, Instruction instr, Address endAddress,
            FlatProgramAPI flatAPI, ReferenceManager refManager, int maxIndex) throws Exception {
        // Add initial comment and reference
        Address immediateValueAddress = instr.getAddress().add(1);
        byte[] immediateValueBytes = new byte[1];
        program.getMemory().getBytes(immediateValueAddress, immediateValueBytes);
        String immediateValueInHex = bytesToHex(immediateValueBytes);
        
        flatAPI.setPreComment(instr.getAddress(), "Max Index: " + immediateValueInHex);
        refManager.addMemoryReference(
            instr.getAddress(),
            endAddress,
            RefType.CONDITIONAL_JUMP,
            SourceType.ANALYSIS,
            0);

        // Clear existing data in jump table area
        Address jumpTableAddress = instr.getAddress().add(2);
        try {
            program.getListing().clearCodeUnits(jumpTableAddress, endAddress.subtract(1), false);
        }
        catch (Exception e) {
            throw new Exception("Could not clear jump table area: " + e.getMessage());
        }
    }

    private void processJumpTableEntries(Program program, Instruction instr, 
            Address jumpTableAddress, Address endAddress, FlatProgramAPI flatAPI,
            ReferenceManager refManager, int maxIndex, MessageLog log) {
        for (int i = 0; i <= maxIndex; i++) {
            Address currentAddress = jumpTableAddress.add(i * 2);
            try {
                processJumpTableEntry(program, instr, currentAddress, endAddress, 
                    flatAPI, refManager, i);
            }
            catch (Exception e) {
                log.appendMsg("Warning: Could not process jump table entry at " +
                    currentAddress + ": " + e.getMessage());
            }
        }
    }

    private void processJumpTableEntry(Program program, Instruction instr,
            Address currentAddress, Address endAddress, FlatProgramAPI flatAPI,
            ReferenceManager refManager, int index) throws Exception {
        // Read and parse jump table offset
        byte[] jumpTableOffsetBytes = new byte[2];
        program.getMemory().getBytes(currentAddress, jumpTableOffsetBytes);
        String jumpTableOffsetInHex = bytesToHex(jumpTableOffsetBytes);
        int rawValue = Integer.parseInt(jumpTableOffsetInHex.substring(2), 16);
        short jumpTableOffset = (short)(rawValue & 0xFFFF);  // Ensure 16-bit signed value

        // Create reference to destination
        Address destinationAddress = endAddress.add(jumpTableOffset);
        refManager.addMemoryReference(
            instr.getAddress(),
            destinationAddress,
            RefType.CONDITIONAL_JUMP,
            SourceType.DEFAULT,
            0);

        // Create word data and comment
        flatAPI.createWord(currentAddress);
        flatAPI.setEOLComment(currentAddress,
            "Offset " + index + ": " + jumpTableOffsetInHex);
    }

    private int extractMnemonicSuffix(String mnemonic, String prefix) {
        if (!mnemonic.startsWith(prefix))
            return -1;
        try {
            String suffix = mnemonic.substring(prefix.length());
            return Integer.parseInt(suffix);
        }
        catch (NumberFormatException e) {
            return -1;
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder("0x");
        for (byte b : bytes) {
            hexString.append(String.format("%02X", b));
        }
        return hexString.toString();
    }
}
