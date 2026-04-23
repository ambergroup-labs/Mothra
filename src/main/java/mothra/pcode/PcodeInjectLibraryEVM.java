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

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.InjectPayload;
import ghidra.program.model.lang.PcodeInjectLibrary;

/**
 * Custom PcodeInjectLibrary for EVM.
 *
 * Provides dynamic uponreturn injection that pushes return values (r0, r1, ...)
 * back onto the stk space after a CALL returns. This bridges the gap between
 * register-based return values and stack-based parameters, enabling the
 * decompiler to trace data flow in chained calls.
 */
public class PcodeInjectLibraryEVM extends PcodeInjectLibrary {

	public PcodeInjectLibraryEVM(SleighLanguage l) {
		super(l);
	}

	public PcodeInjectLibraryEVM(PcodeInjectLibraryEVM op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new PcodeInjectLibraryEVM(this);
	}

	@Override
	public InjectPayload allocateInject(String sourceName, String name, int tp) {
		if (tp == InjectPayload.CALLMECHANISM_TYPE) {
			return new InjectPayloadEVMUponReturn(name, sourceName, language, uniqueBase);
		}
		return super.allocateInject(sourceName, name, tp);
	}
}
