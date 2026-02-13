package mothra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import mothra.util.MothraLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class EVMFunctionAnalyzer extends AbstractAnalyzer {
	public EVMFunctionAnalyzer() {
		super("EVM Function Analyzer", "Identify functions in contract",
				AnalyzerType.INSTRUCTION_ANALYZER);
		// Run AFTER reference analysis so we can fix incorrect references
		// that Ghidra's automatic reference analyzer creates
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
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
		Set<Address> entries = new LinkedHashSet<>();

		Memory memory = program.getMemory();
		MemoryBlock[] blocks = memory.getBlocks();

		for (MemoryBlock block : blocks) {

			if (block.isExecute()) {
				monitor.setMessage("Processing memory block: " + block.getName());
				MothraLog.info(this, "[EVMFunctionAnalyzer] Processing memory block: " + block.getName());

				Address entry = block.getStart();
				Function func = program.getFunctionManager().getFunctionAt(entry);
				if (func == null) {
					entries.add(entry);
					log.appendMsg("Added entry point for block " + block.getName() + " at " + entry);
				}

				AddressSetView blockSet = new AddressSet(block.getStart(), block.getEnd());

				// First pass: Fix references for ALL PUSH instructions
				fixAllPushReferences(program, block, blockSet, monitor);

				// Second pass: Set FlowOverride on JUMPs, identify function entries
				InstructionIterator instIter = program.getListing().getInstructions(blockSet, true);

				while (instIter.hasNext()) {
					monitor.checkCancelled();
					Instruction instr = instIter.next();
					String instrMnemonic = instr.getMnemonicString();
					if (instrMnemonic.equals("JUMP") || instrMnemonic.equals("JUMPI")) {
						Instruction last = instr.getPrevious();
						if (last != null) {
							String mnemonic = last.getMnemonicString();

							if (mnemonic.startsWith("PUSH")) {
								Address dest = calculateJumpDestination(program, block, last);
								if (dest != null) {
									fixReferencesForInstruction(program.getReferenceManager(),
											instr, dest, RefType.COMPUTED_JUMP);

									if (instrMnemonic.equals("JUMP")) {
										// Check if tail call: return address doesn't
										// match fall-through, OR fall-through is a
										// different function's entry point.
										Address nextAddr = instr.getAddress()
												.add(instr.getLength());
										if (isTailCall(program, block, last, instr)
												|| entries.contains(nextAddr)) {
											instr.setFlowOverride(FlowOverride.CALL_RETURN);
										} else {
											instr.setFlowOverride(FlowOverride.CALL);
										}
										if (block.contains(dest)) {
											func = program.getFunctionManager().getFunctionAt(dest);
											if (func == null) {
												entries.add(dest);
											}
										}
									} else {
										// JUMPI: FlowOverride.BRANCH is intentionally omitted.
										// It's a no-op — JUMPI's flow type satisfies isJump(),
										// so BRANCH returns the same type unchanged
										// (see FlowOverride.java:129-131).

										if (isDispatcherJumpi(program, instr)
												&& block.contains(dest)) {
											func = program.getFunctionManager().getFunctionAt(dest);
											if (func == null) {
												entries.add(dest);
											}
										}
									}
								}
							} else if (instrMnemonic.equals("JUMP") &&
									(mnemonic.startsWith("SWAP")
									|| mnemonic.equals("POP")
									|| mnemonic.equals("JUMPDEST"))) {
								instr.setFlowOverride(FlowOverride.RETURN);
							}
						}
					}
				}
			}
		}

		// Second pass: now that all entries are known, re-check CALL JUMPs.
		// During the first pass, entries.contains(nextAddr) may have missed
		// function entries that were discovered later. Upgrade CALL → CALL_RETURN
		// where the fall-through address is a function entry point.
		for (MemoryBlock block : blocks) {
			if (!block.isExecute()) continue;
			AddressSetView blockSet = new AddressSet(block.getStart(), block.getEnd());
			InstructionIterator iter = program.getListing().getInstructions(blockSet, true);
			while (iter.hasNext()) {
				monitor.checkCancelled();
				Instruction instr = iter.next();
				if (instr.getMnemonicString().equals("JUMP")
						&& instr.getFlowOverride() == FlowOverride.CALL) {
					Address nextAddr = instr.getAddress().add(instr.getLength());
					if (entries.contains(nextAddr)) {
						instr.setFlowOverride(FlowOverride.CALL_RETURN);
					}
				}
			}
		}

		// Create functions in reverse address order (highest address first).
		// This prevents lower-address functions from absorbing higher-address
		// functions' code via fall-through during CreateFunctionCmd's body
		// computation.
		List<Address> sortedEntries = new ArrayList<>(entries);
		sortedEntries.sort(Collections.reverseOrder());
		for (Address e : sortedEntries) {
			monitor.checkCancelled();
			CreateFunctionCmd createFuncCmd = new CreateFunctionCmd(e);
			createFuncCmd.applyTo(program);

			// Set return type to uint256 for newly created functions
			Function func = program.getFunctionManager().getFunctionAt(e);
			if (func != null) {
				setFunctionReturnType(program, func);
			}
		}

		return true;
	}

	/**
	 * Detect whether a JUMPI instruction is part of the dispatcher's
	 * selector-comparison pattern. The dispatcher routes calls to public
	 * function handlers based on the 4-byte function selector, using the
	 * pattern:
	 *
	 *   PUSH4 &lt;selector&gt;; [DUP]; EQ; [ISZERO]; PUSH &lt;handler&gt;; JUMPI
	 *
	 * These JUMPI targets ARE legitimate function entry points and should
	 * be created as functions. All other JUMPI targets (if/else branches,
	 * error checks, loops) should NOT become separate functions.
	 *
	 * @param program The program being analyzed
	 * @param jumpiInstr The JUMPI instruction to check
	 * @return true if this JUMPI is a dispatcher selector branch
	 */
	private boolean isDispatcherJumpi(Program program, Instruction jumpiInstr) {
		// The instruction before JUMPI is a PUSH (already verified by caller).
		// Walk further back to find the comparison pattern.
		Instruction pushInstr = jumpiInstr.getPrevious();
		if (pushInstr == null || !pushInstr.getMnemonicString().startsWith("PUSH")) {
			return false;
		}

		Instruction current = pushInstr.getPrevious();
		if (current == null) {
			return false;
		}

		String currentMnemonic = current.getMnemonicString();

		// Skip optional ISZERO (used in negated comparisons: EQ; ISZERO; PUSH; JUMPI)
		if (currentMnemonic.equals("ISZERO")) {
			current = current.getPrevious();
			if (current == null) {
				return false;
			}
			currentMnemonic = current.getMnemonicString();
		}

		// Must have EQ at this point for a selector dispatch
		if (!currentMnemonic.equals("EQ")) {
			return false;
		}

		// From EQ, look back up to 3 instructions for a PUSH4 (the 4-byte selector).
		// Typical patterns:
		//   DUP1; PUSH4 selector; EQ          (2 instructions back)
		//   PUSH4 selector; DUP2; EQ          (2 instructions back)
		//   PUSH4 selector; EQ                (1 instruction back)
		Instruction search = current.getPrevious();
		for (int i = 0; i < 3 && search != null; i++) {
			if (search.getMnemonicString().equals("PUSH4")) {
				return true;
			}
			search = search.getPrevious();
		}

		return false;
	}

	/**
	 * Detect whether a PUSH+JUMP call pattern is a tail call.
	 *
	 * EVM internal calls follow this pattern:
	 *   PUSH return_addr    ; where to return after callee finishes
	 *   [DUP/SWAP params]   ; parameters for the callee
	 *   PUSH func_addr      ; callee address
	 *   JUMP                ; call
	 *
	 * If return_addr == next instruction after JUMP, it's a regular call and
	 * FlowOverride.CALL (with fall-through) is correct. If return_addr points
	 * elsewhere, the callee returns to a different location — this is a tail
	 * call and FlowOverride.CALL_RETURN (no fall-through) must be used.
	 *
	 * This method uses references already placed on PUSH instructions by the
	 * fixAllPushReferences pass to identify which PUSHes push code addresses
	 * (pointing to JUMPDESTs), avoiding redundant destination recalculation.
	 *
	 * @param program The program being analyzed
	 * @param block The memory block containing the instructions
	 * @param pushFuncAddr The PUSH instruction immediately before the JUMP
	 * @param jumpInstr The JUMP instruction
	 * @return true if this is a tail call (should use CALL_RETURN)
	 */
	private boolean isTailCall(Program program, MemoryBlock block,
			Instruction pushFuncAddr, Instruction jumpInstr) {
		Address nextAfterJump = jumpInstr.getAddress().add(jumpInstr.getLength());
		ReferenceManager refManager = program.getReferenceManager();

		// Walk backwards from the func_addr PUSH to find the return address PUSH.
		// Between the return address and the func address, there are typically
		// DUP/SWAP instructions that arrange parameters for the callee.
		Instruction current = pushFuncAddr.getPrevious();
		int maxLookback = 20;
		int count = 0;

		while (current != null && count < maxLookback) {
			String mnemonic = current.getMnemonicString();

			if (mnemonic.startsWith("DUP") || mnemonic.startsWith("SWAP")) {
				// Parameter manipulation — skip
				current = current.getPrevious();
				count++;
				continue;
			}

			if (mnemonic.startsWith("PUSH")) {
				// Check if this PUSH has a reference to a JUMPDEST within the block.
				// fixAllPushReferences already created DATA references for all PUSHes
				// whose values point to JUMPDESTs, so we just look up the reference.
				Address returnDest = getJumpdestReferenceTarget(refManager, current, block);
				if (returnDest != null) {
					// This PUSH pushes a valid code address — it's the return address.
					// If it doesn't match the fall-through address, this is a tail call.
					return !returnDest.equals(nextAfterJump);
				}
				// No reference to a JUMPDEST — likely a literal parameter value.
				current = current.getPrevious();
				count++;
				continue;
			}

			if (mnemonic.equals("JUMPDEST")) {
				// Hit a JUMPDEST without finding a return address between
				// it and the callee PUSH. This JUMPDEST is a return point
				// from a prior call. The current PUSH+JUMP reuses the
				// return address pushed before that prior call — this is
				// a chained tail call pattern:
				//   PUSH retAddr; ... PUSH callee1; JUMP[CALL];
				//   JUMPDEST; PUSH callee2; JUMP  ← tail call
				return true;
			}

			// Other instruction type — can't determine
			break;
		}

		// Couldn't find a return address PUSH. This might be a simple
		// unconditional branch rather than a function call.
		return false;
	}

	/**
	 * Get the target address if the instruction has a reference pointing to
	 * an address within the given block. Used to check whether a PUSH instruction
	 * pushes a code address (JUMPDEST) — these references are created by
	 * fixAllPushReferences during the first pass.
	 *
	 * @param refManager The reference manager
	 * @param instr The instruction to check references for
	 * @param block The memory block the target must be within
	 * @return The reference target address, or null if no in-block reference exists
	 */
	private Address getJumpdestReferenceTarget(ReferenceManager refManager,
			Instruction instr, MemoryBlock block) {
		for (Reference ref : refManager.getReferencesFrom(instr.getAddress())) {
			Address dest = ref.getToAddress();
			if (block.contains(dest)) {
				return dest;
			}
		}
		return null;
	}

	/**
	 * Set the return type for a function to uint256.
	 * Uses DYNAMIC storage so the "solc" calling convention (defined in
	 * evm.cspec) automatically assigns register r0 for single-return functions.
	 */
	private void setFunctionReturnType(Program program, Function func) {
		try {
			DataTypeManager dtm = program.getDataTypeManager();
			DataType returnType = dtm.resolve(new Uint256DataType(dtm), DataTypeConflictHandler.REPLACE_HANDLER);

			Register r0 = program.getRegister("r0");
			VariableStorage storage = new VariableStorage(program, r0);
			ReturnParameterImpl returnParam = new ReturnParameterImpl(returnType, storage, program);

			func.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING, returnParam,
					Function.FunctionUpdateType.CUSTOM_STORAGE, true,
					SourceType.ANALYSIS);
		} catch (Exception e) {
			MothraLog.error(this, "Failed to set return type for " + func.getName() + ": " + e.getMessage());
		}
	}

	/**
	 * Fix references for ALL PUSH instructions in the block that push values
	 * that could be jump destinations within the same contract.
	 *
	 * This handles cases where the PUSH instruction is not immediately before
	 * the JUMP/JUMPI, such as in Solidity's internal call pattern:
	 *   PUSH return_addr   <- This needs to be fixed
	 *   DUP parameters
	 *   PUSH func_addr     <- This also needs to be fixed
	 *   JUMP
	 */
	private void fixAllPushReferences(Program program, MemoryBlock block,
			AddressSetView blockSet, TaskMonitor monitor) throws CancelledException {

		InstructionIterator instIter = program.getListing().getInstructions(blockSet, true);
		ReferenceManager refManager = program.getReferenceManager();

		while (instIter.hasNext()) {
			monitor.checkCancelled();
			Instruction instr = instIter.next();

			if (!instr.getMnemonicString().startsWith("PUSH")) {
				continue;
			}

			// Get the pushed value
			Scalar scalar = instr.getScalar(0);
			if (scalar == null) {
				continue;
			}

			long pushedValue = scalar.getUnsignedValue();

			// Only process values that could be jump destinations within a contract
			// (values less than CONTRACT_SPACING = 0x10000)
			// Use Long.compareUnsigned to handle large unsigned values correctly
			// (Java's long is signed, so large values appear negative)
			if (Long.compareUnsigned(pushedValue, 0x10000L) >= 0) {
				continue;
			}

			// Calculate the correct destination address
			long blockBase = block.getStart().getOffset();
			long baseMask = blockBase & 0xFFFF0000L;
			long destOffset = baseMask + pushedValue;

			// Verify destOffset is within valid address range (32-bit for EVM)
			if (Long.compareUnsigned(destOffset, 0xFFFFFFFFL) > 0) {
				continue;
			}

			Address dest = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(destOffset);

			// Only fix if the destination is within the same block and is a JUMPDEST
			if (!block.contains(dest)) {
				continue;
			}

			Instruction destInstr = program.getListing().getInstructionAt(dest);
			if (destInstr == null || !destInstr.getMnemonicString().equals("JUMPDEST")) {
				continue;
			}

			// Fix the references for this PUSH instruction
			fixReferencesForInstruction(refManager, instr, dest, RefType.DATA);
		}
	}

	/**
	 * Calculate the correct jump destination address by adding the memory block's
	 * base address to the pushed value. This is necessary because EVM bytecode
	 * uses relative offsets within a contract, but when multiple contracts are
	 * loaded at different base addresses, the references need to be adjusted.
	 *
	 * @param program The program being analyzed
	 * @param block The memory block containing the instruction
	 * @param pushInstr The PUSH instruction containing the jump offset
	 * @return The correctly calculated destination address, or null if calculation fails
	 */
	private Address calculateJumpDestination(Program program, MemoryBlock block,
			Instruction pushInstr) {
		try {
			// Extract the immediate value from the PUSH instruction
			Scalar scalar = pushInstr.getScalar(0);
			if (scalar == null) {
				return null;
			}

			long pushedValue = scalar.getUnsignedValue();

			// Get the base address of the memory block (contract deployment address)
			long blockBase = block.getStart().getOffset();

			// Calculate base address mask (0xFFFF0000 for 0x10000 spacing)
			// This matches the logic in evm.slaspec: (inst_next & 0xFFFF0000) + p
			long baseMask = blockBase & 0xFFFF0000L;

			// Calculate the correct destination address
			long destOffset = baseMask + pushedValue;

			// If the pushed value is already >= baseMask, it might already be an absolute address
			// In that case, don't add the base again
			if (pushedValue >= baseMask && pushedValue < baseMask + 0x10000L) {
				destOffset = pushedValue;
			}

			Address dest = program.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(destOffset);

			MothraLog.debug(this, String.format(
					"[EVMFunctionAnalyzer] PUSH at %s: pushed=0x%x, blockBase=0x%x, dest=%s",
					pushInstr.getAddress(), pushedValue, blockBase, dest));

			return dest;
		} catch (Exception e) {
			MothraLog.error(this, "Failed to calculate jump destination: " + e.getMessage());
			return null;
		}
	}

	/**
	 * Fix references for an instruction to point to the correct destination.
	 * Removes incorrect references and adds the correct one if needed.
	 *
	 * @param refManager The reference manager
	 * @param instr The instruction to fix references for
	 * @param correctDest The correct destination address
	 * @param refType The reference type to use
	 */
	private void fixReferencesForInstruction(ReferenceManager refManager, Instruction instr,
			Address correctDest, RefType refType) {
		// Remove ALL existing references that don't point to the correct destination
		Reference[] existingRefs = refManager.getReferencesFrom(instr.getAddress());
		boolean hasCorrectRef = false;

		for (Reference ref : existingRefs) {
			if (ref.getToAddress().equals(correctDest)) {
				hasCorrectRef = true;
			} else {
				// Remove any reference that doesn't point to the correct destination
				// This ensures we clean up all incorrect references created by
				// Ghidra's automatic reference analyzer
				refManager.delete(ref);
				MothraLog.debug(this, String.format(
						"[EVMFunctionAnalyzer] Removed incorrect ref from %s to %s (correct dest: %s)",
						instr.getAddress(), ref.getToAddress(), correctDest));
			}
		}

		// Add the correct reference if it doesn't exist
		if (!hasCorrectRef) {
			refManager.addMemoryReference(
					instr.getAddress(),
					correctDest,
					refType,
					SourceType.ANALYSIS,
					0);
			MothraLog.debug(this, String.format(
					"[EVMFunctionAnalyzer] Added correct ref from %s to %s",
					instr.getAddress(), correctDest));
		}
	}

}
