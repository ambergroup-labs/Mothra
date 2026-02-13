package mothra;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import mothra.evm.Opcode;
import mothra.util.MothraLog;

public class InputArgsAnalyzer extends AbstractAnalyzer {

	private final Opcode stackAnalyzer = new Opcode();

	public InputArgsAnalyzer() {
		super("Internal Function Arguments Analyzer",
				"Detect the input argument number for internal functions",
				AnalyzerType.BYTE_ANALYZER);
		// Run AFTER EVMFunctionAnalyzer (which runs at REFERENCE_ANALYSIS.after())
		// to ensure functions are already identified.
		// Priority order: FUNCTION_ANALYSIS < REFERENCE_ANALYSIS < DATA_TYPE_PROPOGATION
		// So we use DATA_TYPE_PROPOGATION to run after REFERENCE_ANALYSIS.after()
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION);
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

			// Analyze all functions in the block using DUP/SWAP body analysis
			processAllFunctionsInBlock(program, block, monitor);
		}

		return true;
	}

	/**
	 * Process all functions in a memory block using a three-phase approach:
	 *
	 * Phase 1: Detect parameter counts for ALL functions.
	 * Phase 2: Set parameters with a default single return, so all callee
	 *          param counts are available before return count analysis.
	 * Phase 3: Iteratively refine return counts until stable — each iteration
	 *          may reveal multi-return callees that feed into caller analysis.
	 *
	 * This two-pass + iterative design ensures that:
	 * - Callee param counts are known before analyzing any caller's returns
	 * - 0-param functions still get return count analysis
	 * - Multi-return callee types propagate to callers across iterations
	 */
	private void processAllFunctionsInBlock(Program program, MemoryBlock block, TaskMonitor monitor)
			throws CancelledException {
		FunctionManager functionManager = program.getFunctionManager();

		MothraLog.info(this, String.format(
				"[InputArgsAnalyzer] Processing functions in block %s (0x%x - 0x%x)",
				block.getName(), block.getStart().getOffset(), block.getEnd().getOffset()));

		// Collect functions that need analysis (skip already-parameterized ones)
		List<Function> functions = new ArrayList<>();
		for (Function func : functionManager.getFunctions(block.getStart(), true)) {
			monitor.checkCancelled();
			if (!block.contains(func.getEntryPoint())) {
				break;
			}
			if (func.getParameterCount() > 0) {
				MothraLog.debug(this, String.format(
						"[InputArgsAnalyzer] Skipping %s - already has %d params",
						func.getName(), func.getParameterCount()));
				continue;
			}
			functions.add(func);
		}

		// ── Phase 1: Detect parameter counts for ALL functions ──
		Map<Function, Integer> paramCounts = new LinkedHashMap<>();
		for (Function func : functions) {
			int paramCount = analyzeParametersFromDupOperations(program, func);
			paramCounts.put(func, paramCount);
		}

		// ── Phase 2: Set parameters with default single return ──
		// This makes all callee param counts visible before return analysis.
		int processedCount = 0;
		for (Map.Entry<Function, Integer> entry : paramCounts.entrySet()) {
			Function func = entry.getKey();
			int paramCount = entry.getValue();
			if (paramCount > 0) {
				try {
					Parameter[] parameters = createParameters(program, paramCount);
					Parameter returnParam = createReturnParameter(program, 1);
					func.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, returnParam,
							Function.FunctionUpdateType.CUSTOM_STORAGE, true,
							SourceType.ANALYSIS, parameters);
					processedCount++;
				} catch (Exception e) {
					MothraLog.error(this, "Phase 2: Failed to set params for "
							+ func.getName() + ": " + e.getMessage());
				}
			}
		}
		if (processedCount > 0) {
			functionManager.invalidateCache(true);
		}

		// ── Phase 3: Iterative return count refinement ──
		// Repeat until return types stabilize (callee return types feed into
		// caller analysis, so multiple passes may be needed).
		final int MAX_ITERATIONS = 5;
		boolean stabilized = false;
		for (int iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
			monitor.checkCancelled();
			boolean changed = false;

			for (Map.Entry<Function, Integer> entry : paramCounts.entrySet()) {
				Function func = entry.getKey();
				int paramCount = entry.getValue();

				int returnCount = analyzeReturnCount(program, func, paramCount);
				if (returnCount < 1) {
					returnCount = 1;
				}

				int currentReturnCount = getReturnCount(func);
				if (returnCount == currentReturnCount) {
					continue;
				}

				MothraLog.info(this, String.format(
						"[InputArgsAnalyzer] Iteration %d: %s return count %d -> %d",
						iteration + 1, func.getName(), currentReturnCount, returnCount));

				try {
					Parameter returnParam = createReturnParameter(program, returnCount);
					if (paramCount > 0) {
						Parameter[] parameters = createParameters(program, paramCount);
						func.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, returnParam,
								Function.FunctionUpdateType.CUSTOM_STORAGE, true,
								SourceType.ANALYSIS, parameters);
					} else {
						// 0-param function: update return only
						func.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, returnParam,
								Function.FunctionUpdateType.CUSTOM_STORAGE, true,
								SourceType.ANALYSIS);
					}
					changed = true;
				} catch (Exception e) {
					MothraLog.error(this, "Phase 3: Failed to update return for "
							+ func.getName() + ": " + e.getMessage());
				}
			}

			if (!changed) {
				stabilized = true;
				MothraLog.info(this, String.format(
						"[InputArgsAnalyzer] Return types stabilized after %d iteration(s)",
						iteration + 1));
				break;
			}
			functionManager.invalidateCache(true);
		}
		if (!stabilized) {
			MothraLog.warn(this, String.format(
					"[InputArgsAnalyzer] Return types did NOT stabilize after %d iterations " +
					"— results may be imprecise (possible mutual recursion)",
					MAX_ITERATIONS));
		}

		MothraLog.info(this, String.format(
				"[InputArgsAnalyzer] Processed %d/%d functions in block %s",
				processedCount, functions.size(), block.getName()));
	}

	/**
	 * Analyze a function's body to detect parameter count from stack access operations.
	 *
	 * EVM internal functions receive parameters on the stack. Solidity's internal
	 * call convention pushes the return address FIRST, then arguments, then the
	 * function address (consumed by JUMP). So at function entry (JUMPDEST), the
	 * stack looks like:
	 *   [param1, param2, ..., paramN, return_addr, caller_stack...]
	 *
	 * Parameters are ON TOP of the return address, not below it.
	 *
	 * When the function accesses these parameters using DUP or SWAP instructions,
	 * we can infer the parameter count by tracking which stack positions are accessed.
	 *
	 * Instructions that access stack elements:
	 * - DUPn: copies the nth stack element (1-indexed from top)
	 * - SWAPn: swaps top with (n+1)th element
	 *
	 * For example (2-param function):
	 *   JUMPDEST          ; stackDepth = 0, stack: [param1, param2, return_addr, ...]
	 *   PUSH0             ; stackDepth = 1
	 *   PUSH1 0x20        ; stackDepth = 2
	 *   DUP3              ; accesses position 3 = param1 (paramIndex = 3 - 2 = 1)
	 *   DUP5              ; accesses position 5 = param2 (paramIndex = 5 - 3 = 2)
	 */
	private int analyzeParametersFromDupOperations(Program program, Function func) {
		Address entry = func.getEntryPoint();
		Instruction instr = program.getListing().getInstructionAt(entry);

		if (instr == null || !instr.getMnemonicString().equals("JUMPDEST")) {
			return 0;
		}

		int stackDepth = 0;  // Tracks items pushed onto stack since function entry
		int maxParamIndex = 0;  // Maximum parameter index accessed (1-based)

		int instructionCount = 0;
		final int MAX_INSTRUCTIONS = 50;

		instr = instr.getNext();
		while (instr != null && instructionCount < MAX_INSTRUCTIONS) {
			String mnemonic = instr.getMnemonicString();

			// Terminal instructions — stop analysis
			if (mnemonic.equals("RETURN") || mnemonic.equals("REVERT") ||
				mnemonic.equals("STOP") || mnemonic.equals("INVALID") ||
				mnemonic.equals("SELFDESTRUCT")) {
				break;
			}

			// JUMPI: skip revert-guard paths and continue analysis past them
			if (mnemonic.equals("JUMPI")) {
				stackDepth += stackAnalyzer.stackChanges(mnemonic);

				Instruction next = instr.getNext();
				if (next != null && isRevertPath(next)) {
					// Fall-through is a revert path — skip to the JUMPI target
					Address target = getJumpiTarget(program, instr);
					if (target != null) {
						Instruction targetInstr = program.getListing().getInstructionAt(target);
						if (targetInstr != null &&
							targetInstr.getMnemonicString().equals("JUMPDEST")) {
							instr = targetInstr.getNext();
							instructionCount++;
							continue;
						}
					}
				}
				// Not a revert guard or can't resolve target — stop
				break;
			}

			// JUMP: handle internal CALL (adjust stack and continue), stop otherwise
			if (mnemonic.equals("JUMP")) {
				FlowOverride flowOverride = instr.getFlowOverride();
				if (flowOverride == FlowOverride.CALL) {
					stackDepth += stackAnalyzer.stackChanges(mnemonic); // JUMP's -1
					Function callee = getCalleeFunction(program, instr);
					int calleeParams = callee != null ? callee.getParameterCount() : 0;
					int calleeReturnCount = callee != null ? getReturnCount(callee) : 1;
					stackDepth -= (calleeParams + 1); // params + return address
					stackDepth += calleeReturnCount;
					// Continue — next instruction is the return JUMPDEST
					instr = instr.getNext();
					instructionCount++;
					continue;
				}
				break; // RETURN, CALL_RETURN, or unknown — stop
			}

			// Normal instruction — check DUP/SWAP for parameter access,
			// then update stack depth
			if (mnemonic.startsWith("DUP")) {
				int dupIndex = extractMnemonicSuffix(mnemonic, "DUP");
				if (dupIndex > 0) {
					int paramIndex = dupIndex - stackDepth;
					if (paramIndex > 0 && paramIndex > maxParamIndex) {
						maxParamIndex = paramIndex;
						MothraLog.debug(this, String.format(
								"[InputArgsAnalyzer] %s: DUP%d at stackDepth=%d -> param%d",
								func.getName(), dupIndex, stackDepth, paramIndex));
					}
				}
			} else if (mnemonic.startsWith("SWAP")) {
				int swapIndex = extractMnemonicSuffix(mnemonic, "SWAP");
				if (swapIndex > 0) {
					int accessPosition = swapIndex + 1;
					int paramIndex = accessPosition - stackDepth;
					if (paramIndex > 0 && paramIndex > maxParamIndex) {
						maxParamIndex = paramIndex;
						MothraLog.debug(this, String.format(
								"[InputArgsAnalyzer] %s: SWAP%d at stackDepth=%d -> param%d",
								func.getName(), swapIndex, stackDepth, paramIndex));
					}
				}
			}

			stackDepth += stackAnalyzer.stackChanges(mnemonic);

			if (stackDepth < 0) {
				int consumedParams = -stackDepth;
				if (consumedParams > maxParamIndex) {
					maxParamIndex = consumedParams;
				}
			}

			instr = instr.getNext();
			instructionCount++;
		}

		MothraLog.info(this, String.format(
				"[InputArgsAnalyzer] %s: detected %d params via DUP/SWAP analysis",
				func.getName(), maxParamIndex));

		return maxParamIndex;
	}

	/**
	 * Analyze a function to determine how many values it returns.
	 *
	 * Forward-simulates stack depth from function entry to the RETURN JUMP.
	 * At entry, the stack has [param1, ..., paramN, return_addr]. At the
	 * RETURN JUMP, the stack must be [return_addr, retval1, ..., retvalM].
	 * The formula is: return_count = param_count + stack_depth_before_return_jump.
	 *
	 * Handles:
	 * - JUMPI with revert fall-through: skips the error path to the target JUMPDEST
	 * - JUMP with CALL override: adjusts stack for callee's consumption and return
	 * - JUMP with CALL_RETURN override: tail call, returns 1 (callee's return count)
	 * - JUMP with RETURN override: computes return count from stack depth
	 */
	private int analyzeReturnCount(Program program, Function func, int paramCount) {
		Address entry = func.getEntryPoint();
		Instruction instr = program.getListing().getInstructionAt(entry);

		if (instr == null || !instr.getMnemonicString().equals("JUMPDEST")) {
			return 1;
		}

		int stackDepth = 0;
		int instructionCount = 0;
		final int MAX_INSTRUCTIONS = 500;

		instr = instr.getNext();
		while (instr != null && instructionCount < MAX_INSTRUCTIONS) {
			String mnemonic = instr.getMnemonicString();

			// Terminal instructions — this path doesn't return normally
			if (mnemonic.equals("RETURN") || mnemonic.equals("REVERT") ||
				mnemonic.equals("STOP") || mnemonic.equals("INVALID") ||
				mnemonic.equals("SELFDESTRUCT")) {
				break;
			}

			if (mnemonic.equals("JUMPI")) {
				stackDepth += stackAnalyzer.stackChanges(mnemonic);

				// Check if fall-through is a revert/error path
				Instruction next = instr.getNext();
				if (next != null && isRevertPath(next)) {
					// Skip to the JUMPI's target JUMPDEST
					Address target = getJumpiTarget(program, instr);
					if (target != null) {
						Instruction targetInstr = program.getListing().getInstructionAt(target);
						if (targetInstr != null &&
							targetInstr.getMnemonicString().equals("JUMPDEST")) {
							instr = targetInstr.getNext();
							instructionCount++;
							continue;
						}
					}
				}
				// If not a revert path or can't resolve target, continue linear walk
			} else if (mnemonic.equals("JUMP")) {
				FlowOverride flowOverride = instr.getFlowOverride();

				if (flowOverride == FlowOverride.RETURN) {
					// This is the function's return JUMP.
					// return_count = paramCount + stackDepth (before JUMP's stack change)
					int returnCount = paramCount + stackDepth;
					MothraLog.info(this, String.format(
							"[InputArgsAnalyzer] %s: RETURN JUMP at stackDepth=%d, " +
							"paramCount=%d -> returnCount=%d",
							func.getName(), stackDepth, paramCount, returnCount));
					return Math.max(returnCount, 1);
				} else if (flowOverride == FlowOverride.CALL) {
					// Internal function call — adjust stack for callee's effect.
					// The PUSH ret_addr, DUP params, PUSH func_addr instructions
					// before this JUMP have already been tracked in stackDepth.
					stackDepth += stackAnalyzer.stackChanges(mnemonic); // JUMP's -1

					Function callee = getCalleeFunction(program, instr);
					int calleeParams = 0; // default for unknown callee
					int calleeReturnCount = 1; // default
					if (callee != null) {
						calleeParams = callee.getParameterCount(); // use actual count, even if 0
						// Look up callee's return type to determine return count.
						// Phase 2 ensures callee params are set; Phase 3 iterates
						// so callee return types propagate across iterations.
						calleeReturnCount = getReturnCount(callee);
					}
					stackDepth -= (calleeParams + 1);
					stackDepth += calleeReturnCount;

					MothraLog.debug(this, String.format(
							"[InputArgsAnalyzer] %s: CALL callee=%s params=%d returns=%d -> stackDepth=%d",
							func.getName(),
							callee != null ? callee.getName() : "unknown",
							calleeParams, calleeReturnCount, stackDepth));

					// Continue linear walk — next instruction is the return JUMPDEST
				} else if (flowOverride == FlowOverride.CALL_RETURN) {
					// Tail call — this function's return count = callee's return count.
					Function callee = getCalleeFunction(program, instr);
					if (callee != null) {
						Parameter retParam = callee.getReturn();
						if (retParam != null && retParam.getDataType() != null) {
							int retSize = retParam.getDataType().getLength();
							if (retSize > 32) {
								return retSize / 32;
							}
						}
					}
					return 1; // default
				} else {
					// No flow override — unrecognized pattern, stop analysis
					break;
				}
			} else {
				stackDepth += stackAnalyzer.stackChanges(mnemonic);
			}

			instr = instr.getNext();
			instructionCount++;
		}

		return 1; // default to single return
	}

	/**
	 * Check if the given instruction starts a revert/error path.
	 * Looks ahead up to 15 instructions for a terminal opcode.
	 *
	 * Typical revert paths include PUSH error selector, MSTORE error data,
	 * PUSH offset, PUSH size, REVERT — which can span 7-12 instructions.
	 * A look-ahead of 15 covers these patterns with margin.
	 */
	private boolean isRevertPath(Instruction instr) {
		Instruction current = instr;
		for (int i = 0; i < 15 && current != null; i++) {
			String m = current.getMnemonicString();
			if (m.equals("REVERT") || m.equals("INVALID") ||
				m.equals("STOP") || m.equals("SELFDESTRUCT")) {
				return true;
			}
			if (m.equals("JUMPDEST") || m.equals("JUMP") || m.equals("JUMPI")) {
				return false;
			}
			current = current.getNext();
		}
		return false;
	}

	/**
	 * Get the target address of a JUMPI from the PUSH instruction before it.
	 */
	private Address getJumpiTarget(Program program, Instruction jumpiInstr) {
		Instruction prev = jumpiInstr.getPrevious();
		if (prev == null || !prev.getMnemonicString().startsWith("PUSH")) {
			return null;
		}
		Scalar scalar = prev.getScalar(0);
		if (scalar == null) {
			return null;
		}
		long pushedValue = scalar.getUnsignedValue();
		long baseMask = jumpiInstr.getAddress().getOffset() & 0xFFFF0000L;
		return program.getAddressFactory().getDefaultAddressSpace()
				.getAddress(baseMask + pushedValue);
	}

	/**
	 * Get the callee function from the PUSH instruction before a CALL JUMP.
	 * Walks backward past DUP/SWAP instructions to find the callee address PUSH,
	 * handling patterns where parameter manipulation occurs between PUSH and JUMP.
	 */
	private Function getCalleeFunction(Program program, Instruction jumpInstr) {
		Instruction current = jumpInstr.getPrevious();
		for (int i = 0; i < 5 && current != null; i++) {
			String mnemonic = current.getMnemonicString();
			if (mnemonic.startsWith("PUSH")) {
				Scalar scalar = current.getScalar(0);
				if (scalar == null) {
					return null;
				}
				long pushedValue = scalar.getUnsignedValue();
				long baseMask = jumpInstr.getAddress().getOffset() & 0xFFFF0000L;
				Address calleeAddr = program.getAddressFactory().getDefaultAddressSpace()
						.getAddress(baseMask + pushedValue);
				return program.getFunctionManager().getFunctionAt(calleeAddr);
			}
			if (mnemonic.startsWith("DUP") || mnemonic.startsWith("SWAP")) {
				current = current.getPrevious();
				continue;
			}
			break; // other instruction — can't determine callee
		}
		return null;
	}

	/**
	 * Get the current return count from a function's return type.
	 * Returns the number of 32-byte return values based on the return type size.
	 */
	private int getReturnCount(Function func) {
		Parameter retParam = func.getReturn();
		if (retParam != null && retParam.getDataType() != null) {
			int retSize = retParam.getDataType().getLength();
			if (retSize > 0) {
				return Math.max(retSize / 32, 1);
			}
		}
		return 1;
	}

	/**
	 * Create parameters with explicit stack-based storage.
	 * Uses stack offsets 0, 32, 64, etc. for each 32-byte parameter.
	 * This matches where the decompiler sees the parameters being accessed.
	 *
	 * Storage is assigned automatically by the "solc" calling convention.
	 */
	private Parameter[] createParameters(Program program, int count) throws InvalidInputException {
		// Capped at 8 to match the cspec's 8 input pentry slots.
		// EVM supports DUP1-DUP16/SWAP1-SWAP16, so functions with >8 params
		// are possible; increasing this requires adding more pentry entries
		// in evm.cspec.
		int actualCount = Math.min(count, 8);
		Parameter[] parameters = new Parameter[actualCount];

		DataTypeManager dtm = program.getDataTypeManager();
		DataType paramType = dtm.resolve(new Uint256DataType(dtm), DataTypeConflictHandler.REPLACE_HANDLER);
		AddressSpace stackSpace = program.getAddressFactory().getStackSpace();

		for (int i = 0; i < actualCount; i++) {
			// Each parameter at byte offset i*32 in stack space
			Varnode stackVarnode = new Varnode(stackSpace.getAddress(i * 32), 32);
			VariableStorage storage = new VariableStorage(program, stackVarnode);
			parameters[i] = new ParameterImpl("param" + (i + 1), paramType, storage, program);
		}
		return parameters;
	}

	/**
	 * Create return parameter with the appropriate data type.
	 * Storage is assigned automatically by the "solc" calling convention
	 * (defined in evm.cspec) when using DYNAMIC_STORAGE_ALL_PARAMS:
	 *
	 * - 1 return (32 bytes):  r0             via cspec output entry 1
	 * - 2 returns (64 bytes): join r0:r1     via cspec output entry 2
	 * - 3 returns (96 bytes): join r0:r1:r2  via cspec output entry 3
	 * - 4 returns (128 bytes): join r0:r1:r2:r3 via cspec output entry 4
	 */
	private Parameter createReturnParameter(Program program, int returnCount)
			throws InvalidInputException {
		DataTypeManager dtm = program.getDataTypeManager();
		DataType uint256Type = dtm.resolve(new Uint256DataType(dtm),
				DataTypeConflictHandler.REPLACE_HANDLER);

		int actualCount = Math.min(returnCount, 4);

		if (actualCount <= 1) {
			Register r0 = program.getRegister("r0");
			VariableStorage storage = new VariableStorage(program, r0);
			return new ReturnParameterImpl(uint256Type, storage, program);
		}

		// Multi-return: create a struct type with uint256 fields
		StructureDataType retStruct = new StructureDataType("uint256x" + actualCount, 0);
		for (int i = 0; i < actualCount; i++) {
			retStruct.add(uint256Type, 32, "val" + (i + 1), null);
		}
		DataType resolvedType = dtm.resolve(retStruct, DataTypeConflictHandler.REPLACE_HANDLER);

		// Create joined register storage: r0:r1, r0:r1:r2, r0:r1:r2:r3
		Register[] regs = new Register[actualCount];
		for (int i = 0; i < actualCount; i++) {
			regs[i] = program.getRegister("r" + i);
		}
		VariableStorage storage = new VariableStorage(program, regs);
		return new ReturnParameterImpl(resolvedType, storage, program);
	}

	private int extractMnemonicSuffix(String mnemonic, String prefix) {
		try {
			return Integer.parseInt(mnemonic.substring(prefix.length()));
		} catch (NumberFormatException e) {
			return -1;
		}
	}
}
