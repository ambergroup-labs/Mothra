package mothra;

import java.util.ArrayList;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMFunctionAnalyzer extends AbstractAnalyzer {
	public EVMFunctionAnalyzer() {
		super("EVM Function Analyzer", "Identify functions in contract",
				AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		boolean canAnalyze = program.getLanguage().getProcessor().equals(
				Processor.findOrPossiblyCreateProcessor("EVM"));

		return canAnalyze;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ArrayList<Address> entries = new ArrayList<Address>();

		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		for (MemoryBlock block : blocks) {

			if (block.isExecute()) {
				monitor.setMessage("Processing memory block: " + block.getName());

				System.out.println("[EVMFunctionAnalyzer] Processing memory block: " + block.getName());

				Address entry = block.getStart();
				Function func = program.getFunctionManager().getFunctionAt(entry);
				if (func == null) {
					entries.add(entry);
					log.appendMsg("Added entry point for block " + block.getName() + " at " + entry);
				}

				AddressSetView blockSet = new AddressSet(block.getStart(), block.getEnd());
				InstructionIterator instIter = program.getListing().getInstructions(blockSet, true);

				while (instIter.hasNext()) {
					monitor.checkCancelled();
					Instruction instr = instIter.next();
					if (instr.getMnemonicString().equals("JUMP")) {
						Instruction last = instr.getPrevious();
						if (last != null) {
							String mnemonic = last.getMnemonicString();

							if (mnemonic.startsWith("PUSH")) {
								Reference[] references = program.getReferenceManager()
										.getReferencesFrom(instr.getAddress());
								if (references != null && references.length == 1) {
									Address dest = references[0].getToAddress();
									if (dest != null) {
										instr.setFlowOverride(FlowOverride.CALL);

										// Check if destination is within the same block
										if (block.contains(dest)) {
											func = program.getFunctionManager().getFunctionAt(dest);
											if (func == null) {
												entries.add(dest);
											}
										}
									}
								}
							} else if (mnemonic.startsWith("SWAP")
									|| mnemonic.equals("POP")
									|| mnemonic.equals("JUMPDEST")) {
								instr.setFlowOverride(FlowOverride.RETURN);
							}
						}
					}
				}
			}
		}

		for (Address e : entries) {
			monitor.checkCancelled();
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(e);
			createFuncCmd.applyTo(program);
		}

		return true;
	}

}
