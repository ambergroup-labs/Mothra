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
package mothra.trace.builder;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;

import org.jdom.JDOMException;

import db.DBHandle;
import db.Transaction;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.data.OpenMode;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TraceSleighUtils;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.bookmark.*;
import ghidra.trace.database.listing.*;
import ghidra.trace.database.memory.DBTraceMemoryManager;
import ghidra.trace.database.symbol.DBTraceReference;
import ghidra.trace.database.target.DBTraceObjectManager;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.*;
import ghidra.trace.model.guest.TraceGuestPlatform;
import ghidra.trace.model.guest.TracePlatform;
import ghidra.trace.model.memory.TraceRegister;
import ghidra.trace.model.memory.TraceRegisterContainer;
import ghidra.trace.model.symbol.TraceReferenceManager;
import ghidra.trace.model.target.TraceObject;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.schema.*;
import ghidra.trace.model.target.schema.DefaultTraceObjectSchema.DefaultAttributeSchema;
import ghidra.trace.model.target.schema.TraceObjectSchema.Hidden;
import ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceRegisterUtils;
import ghidra.util.Msg;
import mothra.util.MothraLog;
import ghidra.util.exception.*;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * A convenient means of creating a {@link Trace} for testing
 *
 * <p>
 * There are two patterns for using this: 1) {@code try-with-resources}, and 2) in set up and tear
 * down. Some of our abstract test cases include one of these already. The constructors can build or
 * take a trace from a variety of sources, and it provides many methods for accessing parts of the
 * trace and/or program API more conveniently, esp., for generating addresses.
 *
 * <p>
 * The builder is a consumer of the trace and will automatically release it in {@link #close()}.
 */
public class ToyDBTraceBuilder implements AutoCloseable {
	public final Language language;
	public final DBTrace trace;
	public final TracePlatform host;
	public final LanguageService languageService = DefaultLanguageService.getLanguageService();

	public static final String CUSTOM_SCHEMA_XML = """
			<context>
			    <schema name='Session' elementResync='NEVER' attributeResync='ONCE'>
			        <attribute name='Threads' schema='ThreadContainer' />
			        <attribute name='Memory' schema='MemoryContainer' />
			        <attribute name='Modules' schema='ModuleContainer' />
			    </schema>
			    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER' attributeResync='NEVER'>
			        <element schema='Thread' />
			    </schema>
			    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Thread' />
			        <interface name='Activatable' />
			        <interface name='Aggregate' />
			        <attribute name='_tid' schema='INT' />
			        <attribute name='_name' schema='STRING' />
			        <attribute name='_display' schema='STRING' />
			        <attribute name='_state' schema='STRING' />
			        <attribute name='_pc' schema='ADDRESS' />
			        <attribute name='Stack' schema='Stack' />
			        <attribute name='Registers' schema='RegisterContainer' />
			    </schema>
			    <schema name='Stack' canonical='yes' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Stack' />
			        <element schema='Frame' />
			    </schema>
			    <schema name='Frame' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='StackFrame' />
			        <attribute name='_pc' schema='ADDRESS' />
			        <attribute name='_display' schema='STRING' />
			        <attribute name='Registers' schema='RegisterContainer' />
			    </schema>
			    <schema name='RegisterContainer' canonical='yes' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='RegisterContainer' />
			        <element schema='Register' />
			    </schema>
			    <schema name='Register' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Register' />
			    </schema>
			    <schema name='MemoryContainer' canonical='yes' elementResync='NEVER' attributeResync='NEVER'>
			        <element schema='MemoryRegion' />
			    </schema>
			    <schema name='MemoryRegion' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='MemoryRegion' />
			        <attribute name='_range' schema='RANGE' />
			        <attribute name='_readable' schema='BOOL' />
			        <attribute name='_writable' schema='BOOL' />
			        <attribute name='_executable' schema='BOOL' />
			    </schema>
			    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER' attributeResync='NEVER'>
			        <element schema='Module' />
			    </schema>
			    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
			        <interface name='Module' />
			        <attribute name='_module_name' schema='STRING' />
			        <attribute name='_range' schema='RANGE' />
			    </schema>
			</context>
			""";

	public static final SchemaContext CTX_DEFAULT;

	static {
		try {
			CTX_DEFAULT = XmlSchemaContext.deserialize(CUSTOM_SCHEMA_XML);
		}
		catch (JDOMException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Open a .gzf compressed trace
	 *
	 * @param file the .gzf file containing the trace
	 * @throws CancelledException never, since the monitor cannot be cancelled
	 * @throws VersionException if the trace's version is not as expected
	 * @throws LanguageNotFoundException if the trace's language cannot be found
	 * @throws IOException if there's an issue accessing the file
	 */
	public ToyDBTraceBuilder(File file)
			throws CancelledException, VersionException, LanguageNotFoundException, IOException {
		DBHandle handle = new DBHandle(file);
		this.trace = new DBTrace(handle, OpenMode.UPDATE, new ConsoleTaskMonitor(), this);
		this.language = trace.getBaseLanguage();
		this.host = trace.getPlatformManager().getHostPlatform();
	}

	/**
	 * Create a new trace with the given name and language
	 *
	 * @param name the name
	 * @param langID the id of the language, as in {@link LanguageID}
	 * @throws IOException if there's an issue creating the trace's database file(s)
	 */
	// TODO: A constructor for specifying compiler, too
	public ToyDBTraceBuilder(String name, String langID) throws IOException {
		this.language = languageService.getLanguage(new LanguageID(langID));
		this.trace = new DBTrace(name, language.getDefaultCompilerSpec(), this);
		this.host = trace.getPlatformManager().getHostPlatform();
	}

	/**
	 * Adopt the given trace
	 *
	 * <p>
	 * The builder will add itself as a consumer of the trace, so the caller may safely release it.
	 *
	 * @param trace the trace
	 */
	public ToyDBTraceBuilder(Trace trace) {
		this.language = trace.getBaseLanguage();
		this.trace = (DBTrace) trace;
		this.host = trace.getPlatformManager().getHostPlatform();
		trace.addConsumer(this);
	}

	/**
	 * Manipulate the trace's memory and registers using Sleigh
	 *
	 * @param snap the snap to modify
	 * @param thread the thread to modify, can be {@code null} if only memory is used
	 * @param frame the frame to modify
	 * @param sleigh the Sleigh source
	 */
	public void exec(long snap, TraceThread thread, int frame, String sleigh) {
		PcodeProgram program = SleighProgramCompiler.compileProgram((SleighLanguage) language,
			"builder", sleigh, PcodeUseropLibrary.nil());
		TraceSleighUtils.buildByteExecutor(trace, snap, thread, frame)
				.execute(program, PcodeUseropLibrary.nil());
	}

	/**
	 * Manipulate the trace's memory and registers using Sleigh
	 *
	 * @param platform the platform whose language to use
	 * @param snap the snap to modify
	 * @param thread the thread to modify, can be {@code null} if only memory is used
	 * @param frame the frame to modify
	 * @param sleigh the lines of Sleigh, including semicolons.
	 */
	public void exec(TracePlatform platform, long snap, TraceThread thread, int frame,
			String sleigh) {
		TraceSleighUtils.buildByteExecutor(platform, snap, thread, frame)
				.execute(
					SleighProgramCompiler.compileProgram((SleighLanguage) platform.getLanguage(),
						"builder", sleigh, PcodeUseropLibrary.nil()),
					PcodeUseropLibrary.nil());
	}

	/**
	 * Get the named register
	 *
	 * @param name the name
	 * @return the register or null if it doesn't exist
	 */
	public Register reg(String name) {
		return language.getRegister(name);
	}

	/**
	 * Get the named register
	 *
	 * @param platform the platform
	 * @param name the name
	 * @return the register or null if it doesn't exist
	 */
	public Register reg(TracePlatform platform, String name) {
		return platform.getLanguage().getRegister(name);
	}

	/**
	 * A shortcut for {@code space.getAdddress(offset)}
	 *
	 * @param space the space
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(AddressSpace space, long offset) {
		return space.getAddress(offset);
	}

	/**
	 * Create an address in the given language's default space
	 *
	 * @param lang the language
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(Language lang, long offset) {
		return addr(lang.getDefaultSpace(), offset);
	}

	/**
	 * Create an address in the trace's default space
	 *
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(long offset) {
		return addr(language, offset);
	}

	/**
	 * Create an address in the given platform's default space
	 *
	 * @param platform the platform
	 * @param offset the offset
	 * @return the address
	 */
	public Address addr(TracePlatform platform, long offset) {
		return platform.getLanguage().getDefaultSpace().getAddress(offset);
	}

	/**
	 * Create an address in the given language's default data space
	 *
	 * @param lang the language
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(Language lang, long offset) {
		return addr(lang.getDefaultDataSpace(), offset);
	}

	/**
	 * Create an address in the trace's default data space
	 *
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(long offset) {
		return data(language, offset);
	}

	/**
	 * Create an address in the given platform's default data space
	 *
	 * @param platform the platform
	 * @param offset the offset
	 * @return the address
	 */
	public Address data(TraceGuestPlatform platform, long offset) {
		return data(platform.getLanguage(), offset);
	}

	/**
	 * Create an address range: shortcut for {@link AddressRangeImpl}
	 *
	 * @param start the start address
	 * @param end the end address
	 * @return the range
	 */
	public AddressRange range(Address start, Address end) {
		return new AddressRangeImpl(start, end);
	}

	/**
	 * Create an address range in the given space with the given start and end offsets
	 *
	 * @param space the space
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(AddressSpace space, long start, long end) {
		return range(addr(space, start), addr(space, end));
	}

	/**
	 * Create an address range in the given language's default space
	 *
	 * @param lang the language
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(Language lang, long start, long end) {
		return range(lang.getDefaultSpace(), start, end);
	}

	/**
	 * Create an address range in the trace's default space
	 *
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(long start, long end) {
		return range(language, start, end);
	}

	/**
	 * Create a singleton address range in the trace's default space
	 *
	 * @param singleton the offset
	 * @return the range
	 */
	public AddressRange range(long singleton) {
		return range(singleton, singleton);
	}

	/**
	 * Create an address-span box in the trace's default space with a singleton snap
	 *
	 * @param snap the snap
	 * @param start the start address offset
	 * @param end the end address offset
	 * @return the box
	 */
	public TraceAddressSnapRange srange(long snap, long start, long end) {
		return new ImmutableTraceAddressSnapRange(addr(start), addr(end), snap, snap);
	}

	/**
	 * Create an address range in the given language's default data space
	 *
	 * @param lang the language
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(Language lang, long start, long end) {
		return range(language.getDefaultDataSpace(), start, end);
	}

	/**
	 * Create an address range in the trace's default data space
	 *
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(long start, long end) {
		return drng(language, start, end);
	}

	/**
	 * Create an address range in the given platform's default space
	 *
	 * @param platform the platform
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange range(TracePlatform platform, long start, long end) {
		return range(platform.getLanguage(), start, end);
	}

	/**
	 * Create an address range in the given platform's default data space
	 *
	 * @param platform the platform
	 * @param start the start offset
	 * @param end the end offset
	 * @return the range
	 */
	public AddressRange drng(TracePlatform platform, long start, long end) {
		return drng(platform.getLanguage(), start, end);
	}

	/**
	 * Create an address set from the given ranges
	 *
	 * @param ranges the ranges
	 * @return the set
	 */
	public AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange rng : ranges) {
			result.add(rng);
		}
		return result;
	}

	/**
	 * Create a byte array
	 *
	 * <p>
	 * This is basically syntactic sugar, since expressing a byte array literal can get obtuse in
	 * Java. {@code new byte[] {0, 1, 2, (byte) 0x80, (byte) 0xff}} vs
	 * {@code arr(0, 1, 2, 0x80, 0xff)}.
	 *
	 * @param e the bytes' values
	 * @return the array
	 */
	public byte[] arr(int... e) {
		byte[] result = new byte[e.length];
		for (int i = 0; i < e.length; i++) {
			result[i] = (byte) e[i];
		}
		return result;
	}

	/**
	 * Create a byte buffer
	 *
	 * @param e the bytes' values
	 * @return the buffer, positioned at 0
	 */
	public ByteBuffer buf(int... e) {
		return ByteBuffer.wrap(arr(e));
	}

	/**
	 * Create a byte buffer, filled with a UTF-8 encoded string
	 *
	 * @param str the string to encode
	 * @return the buffer, positioned at 0
	 */
	public ByteBuffer buf(String str) {
		CharsetEncoder ce = Charset.forName("UTF-8").newEncoder();
		ByteBuffer result =
			ByteBuffer.allocate(Math.round(ce.maxBytesPerChar() * str.length()) + 1);
		ce.encode(CharBuffer.wrap(str), result, true);
		result.put((byte) 0);
		return result.flip();
	}

	public class EventSuspension implements AutoCloseable {
		public EventSuspension() {
			trace.setEventsEnabled(false);
		}

		@Override
		public void close() {
			trace.setEventsEnabled(true);
		}
	}

	/**
	 * Start a transaction on the trace
	 *
	 * <p>
	 * Use this in a {@code try-with-resources} block
	 *
	 * @return the transaction handle
	 */
	public Transaction startTransaction() {
		return trace.openTransaction("Testing");
	}

	/**
	 * Suspend events for the trace
	 *
	 * <p>
	 * Use this in a {@code try-with-resources} block
	 *
	 * @return the suspension handle
	 */
	public EventSuspension suspendEvents() {
		return new EventSuspension();
	}

	/**
	 * Ensure the given bookmark type exists and retrieve it
	 *
	 * @param name the name of the type
	 * @return the type
	 */
	public DBTraceBookmarkType getOrAddBookmarkType(String name) {
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		return manager.defineBookmarkType(name, null, Messages.ERROR, 1);
	}

	/**
	 * Add a bookmark to the trace
	 *
	 * @param snap the starting snap
	 * @param addr the address
	 * @param typeName the name of its type
	 * @param category the category
	 * @param comment an optional comment
	 * @return the new bookmark
	 */
	public DBTraceBookmark addBookmark(long snap, long addr, String typeName, String category,
			String comment) {
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmark bm =
			manager.addBookmark(Lifespan.nowOn(snap), addr(addr), type, category, comment);
		return bm;
	}

	/**
	 * Add a bookmark on a register in the trace
	 *
	 * @param snap the starting snap
	 * @param threadName the name of the thread
	 * @param registerName the name of the register
	 * @param typeName the name of its type
	 * @param category the category
	 * @param comment an optional comment
	 * @return the new bookmark
	 */
	public DBTraceBookmark addRegisterBookmark(long snap, String threadName, String registerName,
			String typeName, String category, String comment) {
		Register register = language.getRegister(registerName);
		if (register == null) {
			throw new IllegalArgumentException("Register not found: " + registerName);
		}
		TraceThread thread = getOrAddThread(threadName, snap);
		// Create registers for the thread if needed
		createObjectsRegsForThread(thread, Lifespan.nowOn(0), host);
		DBTraceBookmarkType type = getOrAddBookmarkType(typeName);
		DBTraceBookmarkManager manager = trace.getBookmarkManager();
		DBTraceBookmarkSpace space = manager.getBookmarkRegisterSpace(thread, true);
		DBTraceBookmark bm = (DBTraceBookmark) space.addBookmark(Lifespan.nowOn(snap), register,
			type, category, comment);
		return bm;
	}

	/**
	 * Create a data unit
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param type the data type of the unit
	 * @param length the length, or -1 for the type's default
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, DataType type, int length)
			throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		return code.definedData().create(Lifespan.nowOn(snap), start, type, length);
	}

	/**
	 * Create a data unit
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform for data organization
	 * @param type the data type of the unit
	 * @param length the length, or -1 for the type's default
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, TracePlatform platform,
			DataType type, int length) throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		return code.definedData().create(Lifespan.nowOn(snap), start, platform, type, length);
	}

	/**
	 * Create a data unit, first placing the given bytes
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param type the data type of the unit
	 * @param buf the bytes to place, which will become the unit's bytes
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, DataType type, ByteBuffer buf)
			throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceDataAdapter data = addData(snap, start, type, length);
		return data;
	}

	/**
	 * Create a data unit, first placing the given bytes
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform for data organization
	 * @param type the data type of the unit
	 * @param buf the bytes to place, which will become the unit's bytes
	 * @return the new data unit
	 * @throws CodeUnitInsertionException if the unit cannot be created
	 */
	public DBTraceDataAdapter addData(long snap, Address start, TracePlatform platform,
			DataType type, ByteBuffer buf) throws CodeUnitInsertionException {
		int length = buf.remaining();
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceDataAdapter data = addData(snap, start, platform, type, length);
		return data;
	}

	/**
	 * Create an instruction unit by disassembling existing bytes
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform for the language to disassemble
	 * @return the instruction unit
	 * @throws CodeUnitInsertionException if the instruction cannot be created
	 */
	public DBTraceInstruction addInstruction(long snap, Address start, TracePlatform platform)
			throws CodeUnitInsertionException {
		DBTraceCodeManager code = trace.getCodeManager();
		Language platformLanguage = platform.getLanguage();
		Disassembler dis =
			Disassembler.getDisassembler(platformLanguage, platformLanguage.getAddressFactory(),
				new ConsoleTaskMonitor(), msg -> Msg.info(this, "Listener: " + msg));
		RegisterValue defaultContextValue = trace.getRegisterContextManager()
				.getDefaultContext(platformLanguage)
				.getDefaultDisassemblyContext();

		MemBuffer memBuf = platform.getMappedMemBuffer(snap, platform.mapHostToGuest(start));
		InstructionBlock block = dis.pseudoDisassembleBlock(memBuf, defaultContextValue, 1);
		Instruction pseudoIns = block.iterator().next();
		return code.instructions()
				.create(Lifespan.nowOn(snap), start, platform, pseudoIns.getPrototype(), pseudoIns,
					0);
	}

	/**
	 * Create an instruction unit, first placing the given bytes, and disassembling
	 *
	 * @param snap the starting snap
	 * @param start the min address
	 * @param platform the platform for the language to disassemble
	 * @param buf the bytes to place, which will become the unit's bytes
	 * @return the instruction unit
	 * @throws CodeUnitInsertionException if the instruction cannot be created
	 */
	public DBTraceInstruction addInstruction(long snap, Address start, TracePlatform platform,
			ByteBuffer buf) throws CodeUnitInsertionException {
		DBTraceMemoryManager memory = trace.getMemoryManager();
		memory.putBytes(snap, start, buf);
		DBTraceInstruction instruction = addInstruction(snap, start, platform);
		return instruction;
	}

	/**
	 * Ensure the given thread exists and retrieve it
	 *
	 * @param name the thread's name
	 * @param creationSnap the snap where the thread must exist
	 * @return the thread
	 */
	public TraceThread getOrAddThread(String name, long creationSnap) {
		DBTraceThreadManager manager = trace.getThreadManager();
		Collection<? extends TraceThread> threads = manager.getThreadsByPath(name);
		if (threads != null && !threads.isEmpty()) {
			return threads.iterator().next();
		}
		try {
			return manager.createThread(name, creationSnap);
		}
		catch (DuplicateNameException e) {
			throw new AssertionError(e);
		}
	}

	/**
	 * Add a mnemonic memory reference
	 *
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @return the reference
	 */
	public DBTraceReference addMemoryReference(long creationSnap, Address from, AddressRange to) {
		return addMemoryReference(creationSnap, from, to, -1);
	}

	/**
	 * Add an operand memory reference
	 *
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param operandIndex the operand index, or -1 for mnemonic
	 * @return the reference
	 */
	public DBTraceReference addMemoryReference(long creationSnap, Address from, AddressRange to,
			int operandIndex) {
		return trace.getReferenceManager()
				.addMemoryReference(Lifespan.nowOn(creationSnap), from, to, RefType.DATA,
					SourceType.DEFAULT, operandIndex);
	}

	/**
	 * Add a base-offset memory reference
	 *
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param toAddrIsBase true if {@code to} is the base address, implying offset must be added to
	 *            get the real to address.
	 * @param offset the offset
	 * @return the reference
	 */
	public DBTraceReference addOffsetReference(long creationSnap, Address from, Address to,
			boolean toAddrIsBase, long offset) {
		return trace.getReferenceManager()
				.addOffsetReference(Lifespan.nowOn(creationSnap), from, to, toAddrIsBase, offset,
					RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Add a shifted memory reference
	 *
	 * <p>
	 * TODO: This uses opIndex -1, which doesn't make sense for a shifted reference. The "to"
	 * address is computed (I assume by the analyzer which places such reference) as the operand
	 * value shifted by the given shift amount. What is the opIndex for a data unit? Probably 0,
	 * since the "mnemonic" would be its type? Still, this suffices for testing the database.
	 *
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to address
	 * @param shift the shift
	 * @return the reference
	 */
	public DBTraceReference addShiftedReference(long creationSnap, Address from, Address to,
			int shift) {
		return trace.getReferenceManager()
				.addShiftedReference(Lifespan.nowOn(creationSnap), from, to, shift, RefType.DATA,
					SourceType.DEFAULT, -1);
	}

	/**
	 * Add a register reference
	 *
	 * <p>
	 * See
	 * {@link TraceReferenceManager#addRegisterReference(Lifespan, Address, Register, RefType, SourceType, int)}
	 * regarding potential confusion of the word "register" in this context.
	 *
	 * @param creationSnap the starting snap
	 * @param from the from register
	 * @param to the to address
	 * @return the reference
	 */
	public DBTraceReference addRegisterReference(long creationSnap, Address from, String to) {
		return trace.getReferenceManager()
				.addRegisterReference(Lifespan.nowOn(creationSnap), from, language.getRegister(to),
					RefType.DATA, SourceType.DEFAULT, -1);
	}

	/**
	 * Add a stack reference
	 *
	 * <p>
	 * See
	 * {@link TraceReferenceManager#addStackReference(Lifespan, Address, int, RefType, SourceType, int)}
	 * regarding potential confusion of the word "stack" in this context.
	 *
	 * @param creationSnap the starting snap
	 * @param from the from address
	 * @param to the to stack offset
	 * @return the reference
	 */
	public DBTraceReference addStackReference(long creationSnap, Address from, int to) {
		return trace.getReferenceManager()
				.addStackReference(Lifespan.nowOn(creationSnap), from, to, RefType.DATA,
					SourceType.DEFAULT, -1);
	}

	/**
	 * Save the trace to a temporary .gzf file
	 *
	 * @return the new file
	 * @throws IOException if the trace could not be saved
	 * @throws CancelledException never, since the monitor cannot be cancelled
	 */
	public File save() throws IOException, CancelledException {
		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		trace.getObjectManager().flushWbCaches();
		trace.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());
		return tmp.toFile();
	}

	/**
	 * Get the language with the given ID, as in {@link LanguageID}
	 *
	 * @param id the ID
	 * @return the language
	 * @throws LanguageNotFoundException if the language does not exist
	 */
	public Language getLanguage(String id) throws LanguageNotFoundException {
		return languageService.getLanguage(new LanguageID(id));
	}

	/**
	 * Get the compiler spec with the given language and compiler IDs
	 *
	 * @param langID the language ID as in {@link LanguageID}
	 * @param compID the compiler ID as in {@link CompilerSpecID}
	 * @return the compiler spec
	 * @throws CompilerSpecNotFoundException if the compiler spec does not exist
	 * @throws LanguageNotFoundException if the language does not exist
	 */
	public CompilerSpec getCompiler(String langID, String compID)
			throws CompilerSpecNotFoundException, LanguageNotFoundException {
		return getLanguage(langID).getCompilerSpecByID(new CompilerSpecID(compID));
	}

	public TraceThread createObjectsProcessAndThreads() {
		DBTraceObjectManager objs = trace.getObjectManager();
		Lifespan zeroOn = Lifespan.nowOn(0);

		// Create Threads container (required for ThreadManager to find threads)
		KeyPath pathThreads = KeyPath.parse("Threads");
		TraceObject threadsContainer = objs.createObject(pathThreads);
		threadsContainer.insert(zeroOn, ConflictResolution.DENY);

		// Create Thread[1] element (single thread at index 1)
		KeyPath pathThread1 = pathThreads.index(1);
		TraceObject threadObj = objs.createObject(pathThread1);
		threadObj.insert(zeroOn, ConflictResolution.DENY);

		return threadObj.queryInterface(TraceThread.class);
	}

	/**
	 * Create the Modules container in the object model
	 * This is required for the Time window to properly display module information.
	 */
	public void createObjectsModulesContainer() {
		DBTraceObjectManager objs = trace.getObjectManager();
		Lifespan zeroOn = Lifespan.nowOn(0);

		// Create Modules container
		KeyPath pathModules = KeyPath.parse("Modules");
		TraceObject modulesContainer = objs.createObject(pathModules);
		modulesContainer.insert(zeroOn, ConflictResolution.DENY);
	}

	/**
	 * Create the Memory container in the object model
	 * This is required for the debugger to properly display memory regions.
	 */
	public void createObjectsMemoryContainer() {
		DBTraceObjectManager objs = trace.getObjectManager();
		Lifespan zeroOn = Lifespan.nowOn(0);

		// Create Memory container
		KeyPath pathMemory = KeyPath.parse("Memory");
		TraceObject memoryContainer = objs.createObject(pathMemory);
		memoryContainer.insert(zeroOn, ConflictResolution.DENY);
	}

	/**
	 * Create stack and frame objects using the StackManager API
	 * This ensures proper integration with Ghidra's debugger Time window.
	 *
	 * @param thread The thread to create stack for
	 * @param snap The snapshot number
	 * @param initialPc Initial program counter value
	 * @return The created TraceStack
	 */
	public ghidra.trace.model.stack.TraceStack createStackWithFrame(TraceThread thread, long snap,
			ghidra.program.model.address.Address initialPc) {
		try {
			// Use StackManager API to create stack and frame
			ghidra.trace.model.stack.TraceStack stack = trace.getStackManager().getStack(thread, snap, true);

			// Ensure frame 0 exists and set its PC
			ghidra.trace.model.stack.TraceStackFrame frame = stack.getFrame(snap, 0, true);
			if (frame != null && initialPc != null) {
				frame.setProgramCounter(Lifespan.nowOn(snap), initialPc);
			}

			MothraLog.debug(this, "Created stack and frame via StackManager: " +
				thread.getObject().getCanonicalPath() + ".Stack");

			return stack;
		} catch (Exception e) {
			MothraLog.error(this, "Error creating stack: " + e.getMessage());
			return null;
		}
	}

	public void createObjectsRegsForThread(TraceThread thread, Lifespan lifespan,
			TracePlatform platform) {
		DBTraceObjectManager objs = trace.getObjectManager();
		KeyPath pathThread = thread.getObject().getCanonicalPath();
		KeyPath pathContainer = pathThread.key("Registers");

		// CRITICAL: Create the Registers container object first!
		TraceObject containerObj = objs.createObject(pathContainer);
		containerObj.insert(lifespan, ConflictResolution.DENY);

		// Verify it has RegisterContainer interface
		if (containerObj.queryInterface(TraceRegisterContainer.class) == null) {
			throw new IllegalStateException(
				"Registers container not at expected path in schema: " + pathContainer);
		}

		// Now create individual register objects
		for (Register reg : platform.getLanguage().getRegisters()) {
			TraceObject regObj = objs.createObject(pathContainer.index(reg.getName()));
			if (regObj.queryInterface(TraceRegister.class) == null) {
				throw new IllegalStateException("Registers not at the expected path in schema");
			}
			regObj.insert(lifespan, ConflictResolution.DENY);
		}
	}

	public TraceObject createRootObject(SchemaContext ctx, String schemaName) {
		return trace.getObjectManager()
				.createRootObject(ctx.getSchema(new SchemaName(schemaName)))
				.getChild();
	}

	public TraceObject createRootObject(SchemaContext ctx) {
		return createRootObject(ctx, "Session");
	}

	public TraceObject createRootObject(String schemaName) {
		return createRootObject(CTX_DEFAULT, schemaName);
	}

	public TraceObject createRootObject() {
		return createRootObject(CTX_DEFAULT);
	}

	/**
	 * Get an object by its canonical path
	 *
	 * @param canonicalPath the canonical path
	 * @return the object or null
	 */
	public TraceObject obj(String canonicalPath) {
		return trace.getObjectManager()
				.getObjectByCanonicalPath(KeyPath.parse(canonicalPath));
	}

	/**
	 * Get an object by its path pattern
	 *
	 * @param path the path pattern <em>at snapshot 0 only!</em>
	 * @return the object or null
	 */
	public TraceObject objAny0(String path) {
		return objAny(path, Lifespan.at(0));
	}

	/**
	 * Get an object by its path pattern intersecting the given lifespan
	 *
	 * @param path the path pattern
	 * @param span the lifespan to search
	 * @return the object or null
	 */
	public TraceObject objAny(String path, Lifespan span) {
		return trace.getObjectManager()
				.getObjectsByPath(span, KeyPath.parse(path))
				.findFirst()
				.orElse(null);
	}

	/**
	 * Get the value (not value entry) of an object
	 *
	 * @param obj the object
	 * @param snap the snapshot key
	 * @param key the entry key
	 * @return the value, possibly null
	 */
	public Object objValue(TraceObject obj, long snap, String key) {
		TraceObjectValue value = obj.getValue(snap, key);
		return value == null ? null : value.getValue();
	}

	/**
	 * List all values matching the given pattern at the given snap.
	 *
	 * @param snap the snap
	 * @param pattern the pattern
	 * @return the list of values
	 */
	public List<Object> objValues(long snap, String pattern) {
		return trace.getObjectManager()
				.getValuePaths(Lifespan.at(snap), PathFilter.parse(pattern))
				.map(p -> p.getDestinationValue(trace.getObjectManager().getRootObject()))
				.toList();
	}

	@Override
	public void close() {
		if (trace.getConsumerList().contains(this)) {
			// Wait for trace to be unlocked before releasing
			int maxWait = 100; // Max 10 seconds
			int count = 0;
			while (trace.isLocked() && count < maxWait) {
				try {
					Thread.sleep(100);
					count++;
				}
				catch (InterruptedException e) {
					Thread.currentThread().interrupt();
					break;
				}
			}
			trace.release(this);
		}
	}
}
