package mothra;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMDisassembleAnalyzer extends AbstractAnalyzer {
    private static final String EVM_PROCESSOR = "EVM";

    public EVMDisassembleAnalyzer() {
        super("EVM Disassembler", "Disassemble EVM bytecode", AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.BLOCK_ANALYSIS);
        setDefaultEnablement(true);
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getProcessor()
                .equals(Processor.findOrPossiblyCreateProcessor(EVM_PROCESSOR));
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        AddressSet disSet = createDisassemblySet(program);
        disassembleProgram(program, monitor, disSet);
        processInstructions(program, set, monitor, log);
        return true;
    }

    /**
     * Build the set of addresses to disassemble by collecting all executable
     * memory blocks.
     */
    private AddressSet createDisassemblySet(Program program) {
        AddressSet disSet = new AddressSet();
        for (MemoryBlock block : program.getMemory().getBlocks()) {
            if (block.isExecute()) {
                disSet.add(block.getStart(), block.getEnd());
            }
        }
        return disSet;
    }

    private void disassembleProgram(Program program, TaskMonitor monitor, AddressSet disSet) {
        DisassembleCommand cmd = new DisassembleCommand(disSet, null, false);
        cmd.applyTo(program, monitor);
    }

    /**
     * Single-pass processing of all instructions in the analysis set:
     * annotates large PUSH operands with hex comments.
     */
    private void processInstructions(Program program, AddressSetView set, TaskMonitor monitor,
            MessageLog log) throws CancelledException {
        InstructionIterator instIter = program.getListing().getInstructions(set, true);

        while (instIter.hasNext()) {
            monitor.checkCancelled();
            Instruction instr = instIter.next();
            String mnemonic = instr.getMnemonicString();

            if (mnemonic.startsWith("PUSH")) {
                annotateLargePush(program, instr, mnemonic, log);
            }
        }
    }

    /**
     * Add a pre-comment with the full hex value for PUSH9-PUSH32 instructions,
     * whose operands are too large for the listing view to display inline.
     */
    private void annotateLargePush(Program program, Instruction instr, String mnemonic,
            MessageLog log) {
        int byteCount = extractMnemonicSuffix(mnemonic, "PUSH");
        if (byteCount <= 8) {
            return;
        }
        try {
            Address valueStart = instr.getAddress().add(1);
            byte[] valueBytes = new byte[byteCount];
            program.getMemory().getBytes(valueStart, valueBytes);
            program.getListing().setComment(instr.getAddress(), CommentType.PRE,
                    "0x" + bytesToHex(valueBytes));
        } catch (Exception e) {
            log.appendException(e);
        }
    }

    private int extractMnemonicSuffix(String mnemonic, String prefix) {
        if (!mnemonic.startsWith(prefix))
            return -1;
        try {
            return Integer.parseInt(mnemonic.substring(prefix.length()));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /**
     * Convert bytes to hex string without "0x" prefix.
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}
