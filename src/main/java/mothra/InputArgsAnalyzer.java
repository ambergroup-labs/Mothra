package mothra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import mothra.evm.Opcode;

public class InputArgsAnalyzer extends AbstractAnalyzer {

	private final List<Address> entries = new ArrayList<>();
	private final Map<Address, Address> jumpSources = new HashMap<>();
	private final Map<Address, Address> jumpDestinations = new HashMap<>();
	private final Opcode stackAnalyzer = new Opcode();

	public InputArgsAnalyzer() {
		super("Internal Function Arguments Analyzer",
				"Detect the input argument number for internal functions",
				AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.before());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor()
				.equals(Processor.findOrPossiblyCreateProcessor("EVM"));
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		MemoryBlock[] memoryBlocks = program.getMemory().getBlocks();

		for (MemoryBlock block : memoryBlocks) {
			if (monitor.isCancelled()) {
				throw new CancelledException();
			}

			if (!block.isExecute()) {
				continue;
			}

			entries.clear();
			jumpSources.clear();
			jumpDestinations.clear();

			AddressSet blockSet = new AddressSet(block.getStart(), block.getEnd());

			analyzeInstructions(program, blockSet);
			processEntries(program, block);
		}

		return true;
	}

	private void analyzeInstructions(Program program, AddressSetView set) {
		InstructionIterator instructions = program.getListing().getInstructions(set, true);
		Address boundaryStart = null;

		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString();

			if (mnemonic.equals("JUMPDEST")) {
				boundaryStart = instr.getAddress();
			} else if (mnemonic.equals("STOP") || mnemonic.equals("RETURN")) {
				boundaryStart = null;
			} else if (mnemonic.equals("JUMP") || mnemonic.equals("JUMPI")) { // JUMP / JUMPI
				processJumpInstruction(program, instr, boundaryStart);
				boundaryStart = null;
			}
		}
	}

	private void processJumpInstruction(Program program, Instruction instr, Address boundaryStart) {
		Instruction prevInstr = instr.getPrevious();
		if (prevInstr != null && prevInstr.getMnemonicString().startsWith("PUSH")) {
			Reference[] references = program.getReferenceManager().getReferencesFrom(instr.getAddress());
			if (references.length == 1) {
				Address destination = references[0].getToAddress();

				if (destination != null && isValidJump(boundaryStart, destination, program, instr)) {
					jumpSources.put(destination, boundaryStart);
					jumpDestinations.put(boundaryStart, instr.getAddress().add(1));
					entries.add(destination);
				}
			}
		}
	}

	private boolean isValidJump(Address boundaryStart, Address destination, Program program, Instruction instr) {
		return boundaryStart != null &&
				!boundaryStart.equals(destination) &&
				isCallPattern(program, boundaryStart, instr.getAddress().add(1));
	}

	private void processEntries(Program program, MemoryBlock block) {
		for (Address entry : entries) {
			if (entry == null)
				continue;

			Address start = jumpSources.get(entry);

			if (start == null)
				continue;

			Address end = jumpDestinations.get(start);

			if (end == null)
				continue;

			AddressSet addressSet = new AddressSet(start, end);
			int parameterCount = calculateInputParameters(program, addressSet, end);

			defineFunction(program, entry, Math.max(0, parameterCount), block);
		}
	}

	private int calculateInputParameters(Program program, AddressSet addressSet, Address targetAddress) {
		InstructionIterator instructions = program.getListing().getInstructions(addressSet, true);
		ArrayList<Boolean> stackUsage = new ArrayList<>(Collections.nCopies(16, false));
		int stackChange = 0, stackIndex = 0, stackOffset = 16, swapInputs = 0;
		boolean processingInputs = false;

		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString();

			if (mnemonic.startsWith("PUSH")) {
				if (instr.getScalar(0) != null) {
					int pushedAddressValue = (int) instr.getScalar(0).getValue();
					int targetAddressValue = (int) targetAddress.getOffset();

					if (pushedAddressValue == targetAddressValue) {
						processingInputs = true;
						continue;
					}
				}
			}

			if (!processingInputs)
				continue;

			stackChange += stackAnalyzer.stackChanges(mnemonic);

			int opcodeExtractedValue = 0;
			if (mnemonic.startsWith("DUP")) {
				opcodeExtractedValue = extractMnemonicSuffix(mnemonic, "DUP");
				if (stackUsage.get(stackIndex + stackOffset - opcodeExtractedValue) == false) {
					stackUsage.set(stackIndex + stackOffset - opcodeExtractedValue, true);
				}
			} else if (mnemonic.startsWith("SWAP")) {
				opcodeExtractedValue = extractMnemonicSuffix(mnemonic, "SWAP");
				if (stackUsage.get(stackIndex + stackOffset - opcodeExtractedValue) == false) {
					stackUsage.set(stackIndex + stackOffset - opcodeExtractedValue, true);
					swapInputs += 1;
				}
			}

			int absStackChange = Math.abs(stackChange);

			for (int i = 0; i < absStackChange; i++) {
				if (stackChange > 0) {
					stackUsage.add(true);
				} else if (!stackUsage.isEmpty()) {
					stackUsage.remove(stackUsage.size() - 1);
				}
			}
		}

		return stackChange + swapInputs;
	}

	private void defineFunction(Program program, Address entry, int parameterCount, MemoryBlock block) {
		try {
			FunctionManager functionManager = program.getFunctionManager();
			Function function = functionManager.getFunctionAt(entry);

			String functionName = "func_" + entry.toString().replace(":", "_");
			if (function == null) {
				try {
					function = functionManager.createFunction(functionName, entry, null, SourceType.USER_DEFINED);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

			if (function != null) {
				Parameter[] parameters = createParameters(program, parameterCount);

				function.updateFunction(null, null, Function.FunctionUpdateType.CUSTOM_STORAGE, true,
						SourceType.USER_DEFINED, parameters);

				Uint256DataType returnType = new Uint256DataType();
				function.setReturnType(returnType, SourceType.USER_DEFINED);

				program.getFunctionManager().invalidateCache(true);

				try {
					program.flushEvents();
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		} catch (DuplicateNameException | InvalidInputException e) {
			e.printStackTrace();
		}
	}

	private Parameter[] createParameters(Program program, int count) throws InvalidInputException {
		Parameter[] parameters = new Parameter[count];
		Uint256DataType paramType = new Uint256DataType();

		for (int i = 0; i < count; i++) {
			try {
				VariableStorage storage = new VariableStorage(program, paramType.getLength(), i);
				parameters[i] = new ParameterImpl("param" + (i + 1), paramType, storage, program);
			} catch (Exception e) {
				parameters[i] = new ParameterImpl("param" + (i + 1), paramType, program);
			}
		}
		return parameters;
	}

	private int extractMnemonicSuffix(String mnemonic, String prefix) {
		try {
			return Integer.parseInt(mnemonic.substring(prefix.length()));
		} catch (NumberFormatException e) {
			return -1;
		}
	}

	private boolean isCallPattern(Program program, Address start, Address end) {
		AddressSet addressSet = new AddressSet(start, end);
		InstructionIterator instructions = program.getListing().getInstructions(addressSet, true);
		while (instructions.hasNext()) {
			Instruction instr = instructions.next();
			String mnemonic = instr.getMnemonicString();

			if (mnemonic.startsWith("PUSH") && instr.getScalar(0) != null &&
					instr.getScalar(0).getValue() == end.getOffset()) {
				return true;
			}
		}
		return false;
	}
}
