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
package mothra.pcode;

import static ghidra.program.model.pcode.AttributeId.*;
import static ghidra.program.model.pcode.ElementId.*;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.PcodeEmit;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.InjectContext;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.Encoder;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.xml.SpecXmlUtils;
import ghidra.xml.XmlParseException;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlElement;

/**
 * Dynamic uponreturn injection for EVM calling convention.
 *
 * After a CALL returns, this payload pushes the return value registers
 * (r0, r1, ...) back onto the stk space. The number of registers pushed
 * is determined dynamically from the callee's return type size.
 *
 * This bridges the gap between register-based return values (cspec output)
 * and stack-based parameters (cspec input), enabling the decompiler to
 * trace data flow in chained calls like: FUN_A() return → FUN_B() param.
 */
public class InjectPayloadEVMUponReturn implements InjectPayload {

	private String name;
	private String sourceName;
	private InjectParameter[] noParams;

	// Pre-built Varnodes for SP register and r0-r3
	private Varnode spVarnode;
	private Varnode fourConst;       // constant 4 (SP moves by 4 stk address units per push)
	private Varnode[] regVarnodes;   // r0, r1, r2, r3
	private int stkSpaceID;

	public InjectPayloadEVMUponReturn(String nm, String srcName,
			SleighLanguage language, long uniqBase) {
		name = nm;
		sourceName = srcName;
		noParams = new InjectParameter[0];

		AddressSpace constantSpace = language.getAddressFactory().getConstantSpace();
		// SP is 2 bytes (size=2 in slaspec)
		fourConst = new Varnode(constantSpace.getAddress(4), 2);

		// SP register
		Address spAddr = language.getRegister("SP").getAddress();
		spVarnode = new Varnode(spAddr, 2);

		// r0-r7 registers (max 8 return values), each 32 bytes
		regVarnodes = new Varnode[8];
		for (int i = 0; i < 8; i++) {
			Address rAddr = language.getRegister("r" + i).getAddress();
			regVarnodes[i] = new Varnode(rAddr, 32);
		}

		// stk space ID for STORE operations
		AddressSpace stkSpace = language.getAddressFactory().getAddressSpace("stk");
		stkSpaceID = stkSpace.getSpaceID();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public int getType() {
		return CALLMECHANISM_TYPE;
	}

	@Override
	public String getSource() {
		return sourceName;
	}

	@Override
	public int getParamShift() {
		return 0;
	}

	@Override
	public InjectParameter[] getInput() {
		return noParams;
	}

	@Override
	public InjectParameter[] getOutput() {
		return noParams;
	}

	@Override
	public boolean isErrorPlaceholder() {
		return false;
	}

	@Override
	public boolean isFallThru() {
		return true;
	}

	@Override
	public boolean isIncidentalCopy() {
		return false;
	}

	@Override
	public void encode(Encoder encoder) throws IOException {
		encoder.openElement(ELEM_PCODE);
		encoder.writeString(ATTRIB_INJECT, "uponreturn");
		encoder.writeBool(ATTRIB_DYNAMIC, true);
		encoder.closeElement(ELEM_PCODE);
	}

	@Override
	public void inject(InjectContext context, PcodeEmit emit) {
		// Not used for dynamic injection
	}

	@Override
	public PcodeOp[] getPcode(Program program, InjectContext con) {
		// Resolve callee: callAddr may be null/NO_ADDRESS for uponreturn,
		// so fall back to finding the call target from the instruction at baseAddr.
		Function callee = resolveCallee(program, con);
		if (callee == null) {
			mothra.util.MothraLog.debug(this, String.format(
					"[EVM uponreturn] No callee found at baseAddr=%s, skipping", con.baseAddr));
			return new PcodeOp[0];
		}

		// Determine return count from callee's return type
		int returnCount = getReturnCount(callee);
		mothra.util.MothraLog.info(this, String.format(
				"[EVM uponreturn] baseAddr=%s callee=%s returnCount=%d",
				con.baseAddr, callee.getName(), returnCount));
		if (returnCount <= 0) {
			return new PcodeOp[0];
		}

		AddressSpace constantSpace = program.getAddressFactory().getConstantSpace();
		Varnode stkSpaceConst = new Varnode(constantSpace.getAddress(stkSpaceID), 4);

		// Generate pcode: push r[N-1]...r[0] onto stk (reverse order so r0 ends up on top)
		// Each push = 2 pcode ops: SP = SP - 4; STORE *[stk] SP = r[i]
		PcodeOp[] ops = new PcodeOp[returnCount * 2];
		int seqNum = 0;

		for (int i = returnCount - 1; i >= 0; i--) {
			// SP = SP - 4
			PcodeOp sub = new PcodeOp(con.baseAddr, seqNum, PcodeOp.INT_SUB);
			sub.setInput(spVarnode, 0);
			sub.setInput(fourConst, 1);
			sub.setOutput(spVarnode);
			ops[seqNum++] = sub;

			// *[stk] SP = r[i]
			PcodeOp store = new PcodeOp(con.baseAddr, seqNum, PcodeOp.STORE);
			store.setInput(stkSpaceConst, 0);    // target space ID
			store.setInput(spVarnode, 1);          // address = SP
			store.setInput(regVarnodes[i], 2);     // value = r[i]
			ops[seqNum++] = store;
		}

		return ops;
	}

	/**
	 * Resolve the callee function from the injection context.
	 * callAddr may be null/NO_ADDRESS for uponreturn, so we fall back to
	 * finding the call target from references on the instruction at baseAddr.
	 */
	private Function resolveCallee(Program program, InjectContext con) {
		// Try callAddr first
		if (con.callAddr != null && !con.callAddr.equals(Address.NO_ADDRESS)) {
			Function f = program.getFunctionManager().getFunctionAt(con.callAddr);
			if (f != null) {
				return f;
			}
		}

		// Fall back: find CALL reference from the instruction at baseAddr
		ghidra.program.model.symbol.Reference[] refs =
				program.getReferenceManager().getReferencesFrom(con.baseAddr);
		for (ghidra.program.model.symbol.Reference ref : refs) {
			if (ref.getReferenceType().isCall()) {
				Function f = program.getFunctionManager().getFunctionAt(ref.getToAddress());
				if (f != null) {
					return f;
				}
			}
		}

		// Fall back: check FlowOverride on the instruction
		ghidra.program.model.listing.Instruction instr =
				program.getListing().getInstructionAt(con.baseAddr);
		if (instr != null) {
			Address[] flows = instr.getFlows();
			for (Address flowAddr : flows) {
				Function f = program.getFunctionManager().getFunctionAt(flowAddr);
				if (f != null) {
					return f;
				}
			}
		}

		return null;
	}

	/**
	 * Get the number of uint256 return values from a function's return type.
	 */
	private int getReturnCount(Function func) {
		Parameter retParam = func.getReturn();
		if (retParam == null || retParam.getDataType() == null) {
			return 1;
		}
		int retSize = retParam.getDataType().getLength();
		if (retSize <= 0) {
			return 1;
		}
		return Math.max(retSize / 32, 1);
	}

	@Override
	public void restoreXml(XmlPullParser parser, SleighLanguage language)
			throws XmlParseException {
		XmlElement el = parser.start();
		String injectString = el.getAttribute("inject");
		if (injectString == null || !injectString.equals("uponreturn")) {
			throw new XmlParseException("Expecting inject=\"uponreturn\" attribute");
		}
		boolean isDynamic = SpecXmlUtils.decodeBoolean(el.getAttribute("dynamic"));
		if (!isDynamic) {
			throw new XmlParseException("Expecting dynamic attribute");
		}
		parser.end(el);
	}

	@Override
	public boolean isEquivalent(InjectPayload obj) {
		if (getClass() != obj.getClass()) {
			return false;
		}
		InjectPayloadEVMUponReturn op2 = (InjectPayloadEVMUponReturn) obj;
		return name.equals(op2.name) && sourceName.equals(op2.sourceName);
	}
}
