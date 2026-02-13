package mothra.loader;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import db.DBHandle;
import db.DBRecord;
import db.IntField;
import db.LongField;
import db.Schema;
import db.StringField;
import db.Table;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.database.ProgramDB;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mothra.evm.CborDecoder;
import mothra.evm.MetadataObj;
import mothra.trace.data.DataStore;
import mothra.util.MothraLog;
import ghidra.util.Msg;

public class TraceLoader extends AbstractProgramWrapperLoader {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final long CONTRACT_SPACING = 0x10000L;

    private DataStore dataStore;

    public TraceLoader() {
        this.dataStore = null;
    }

    public TraceLoader(DataStore dataStore) {
        this.dataStore = dataStore;
    }

    public void setDataStore(DataStore dataStore) {
        this.dataStore = dataStore;
    }

    @Override
    public String getName() {
        return "Trace Loader";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider p) {
        return List.of(new LoadSpec(this, 0,
                new LanguageCompilerSpecPair("evm:256:default", "default"), true));
    }

    @Override
    protected void load(Program program, ImporterSettings settings)
            throws CancelledException, IOException {

        TaskMonitor mon = settings.monitor();
        MessageLog log = settings.log();

        // Verify DataStore is set
        if (dataStore == null) {
            throw new IOException("DataStore not set. Call setDataStore() before load().");
        }

        mon.initialize(dataStore.getContractList().size() + 1);

        // Deploy contracts from DataStore
        deployContractsFromDataStore(program, mon, log);

        // Store trace data in DB tables
        storeTraceDataInTables(program, mon);

        mon.incrementProgress(1);
        mon.setMessage("TraceLoader: done.");
    }

    private void deployContractsFromDataStore(Program program,
                                              TaskMonitor mon,
                                              MessageLog log)
            throws CancelledException, IOException {

        FlatProgramAPI api = new FlatProgramAPI(program, mon);

        List<String> contracts = dataStore.getContractList();
        Map<String, String> bytecodeMap = dataStore.getContractBytecode();
        Map<String, Long> deploymentAddresses = dataStore.getContractDeploymentAddresses();

        long offset = 0;
        for (String contractAddress : contracts) {
            if (mon.isCancelled()) {
                throw new CancelledException();
            }

            String bytecodeHex = bytecodeMap.get(contractAddress);
            if (bytecodeHex == null || bytecodeHex.isEmpty()) {
                log.appendMsg("Skip contract (no bytecode): " + contractAddress);
                continue;
            }

            byte[] bytecode = hexToBytes(strip0x(bytecodeHex));

            Long deploymentAddr = deploymentAddresses.get(contractAddress);
            if (deploymentAddr != null) {
                offset = deploymentAddr;
            }

            MothraLog.info(this, "Loading contract " + contractAddress + " at offset 0x" +
                             Long.toHexString(offset));

            loadContract(api, program, contractAddress, bytecode, offset, log);
            mon.incrementProgress(1);
            storeContractInfo((ProgramDB) program, contractAddress, offset, log);

            offset += CONTRACT_SPACING;
        }
    }

    private void storeTraceDataInTables(Program program, TaskMonitor mon)
            throws IOException, CancelledException {
        // Store instruction steps from DataStore
        List<DataStore.InstructionStep> steps = dataStore.getInstructionSteps();
        List<Map<String, Object>> structLogsForTable = convertInstructionStepsToStructLogs(steps);
        storeStructLogs((ProgramDB) program, structLogsForTable, mon);

        if (mon.isCancelled()) {
            throw new CancelledException();
        }

        // Store call tracer data
        String callTracerJson = dataStore.getCallTracerData();
        if (callTracerJson != null) {
            Map<String, Object> callTraceData = parseCallTracerJson(callTracerJson);
            storeCallTracerData((ProgramDB) program, callTraceData);
        }
    }

    private List<Map<String, Object>> convertInstructionStepsToStructLogs(
            List<DataStore.InstructionStep> steps) {

        List<Map<String, Object>> logs = new ArrayList<>();

        for (DataStore.InstructionStep step : steps) {
            Map<String, Object> log = new java.util.HashMap<>();
            log.put("pc", (int) step.pc);
            log.put("op", step.op);
            log.put("gas", (int) step.gas);
            log.put("gasCost", (int) step.gasCost);
            log.put("depth", step.depth);
            log.put("stack", step.stack);
            logs.add(log);
        }

        return logs;
    }

    private Map<String, Object> parseCallTracerJson(String json) throws IOException {
        com.fasterxml.jackson.databind.JsonNode root = JSON.readTree(json);
        com.fasterxml.jackson.databind.JsonNode result = root.has("result") ? root.get("result") : root;
        @SuppressWarnings("unchecked")
        Map<String, Object> resultMap = JSON.convertValue(result, Map.class);
        return resultMap;
    }

    private void loadContract(FlatProgramAPI api, Program prog,
            String name, byte[] bytes,
            long base, MessageLog log) throws IOException {

        if (bytes.length == 0) {
            log.appendMsg("Skip " + name);
            return;
        }
        Address addr = prog.getAddressFactory()
                .getDefaultAddressSpace()
                .getAddress(base);

        MemoryBlock block;

        try {
            String blockName = formatContractName(name);
            block = api.createMemoryBlock(blockName, addr, bytes, false);

            block.setRead(true);
            block.setWrite(false);
            block.setExecute(true);
        } catch (Exception e) {
            log.appendException(e);
        }

        api.disassemble(addr);
        //api.addEntryPoint(addr);

        decodeAndAnnotateMetadata(api, bytes, base, log);
    }

    private void decodeAndAnnotateMetadata(FlatProgramAPI api, byte[] bytecode,
            long baseOffset, MessageLog log) throws IOException {
        try {
            int bytesLength = 2;

            if (bytecode.length < bytesLength)
                return;

            int metadataLength = ((bytecode[bytecode.length - 2] & 0xFF) << 8) |
                    (bytecode[bytecode.length - 1] & 0xFF);

            if (bytecode.length - bytesLength - metadataLength <= 0)
                return;

            try {
                MetadataObj metadata = new MetadataObj(bytecode);
                metadata.decodeMetadata();
                CborDecoder decoder = new CborDecoder(api, (int) baseOffset + metadata.getStartIndex(),
                        metadata.getMetadataByteCode());
            } catch (LinkageError e) {
                log.appendMsg("Warning: MetadataObj/CborDecoder not available: " + e.getMessage());
                log.appendMsg("Continuing with basic metadata annotation for contract at offset " + baseOffset);
            } catch (Exception e) {
                log.appendException(e);
                log.appendMsg("Metadata decoding failed for contract at offset " + baseOffset
                        + ", continuing with basic annotation");
            }

            Address a = api.toAddr(baseOffset + bytecode.length - 2);
            api.createWord(a);
            api.setEOLComment(a, "Metadata Length");
        } catch (Exception e) {
            log.appendException(e);
            log.appendMsg("Failed to decode EVM metadata for contract at offset " + baseOffset);
        }
    }

    private static class StructLogAdapter {
        private static final int VER = 1;
        private static final Schema SCHEMA = new Schema(VER, "ID",
                new Class<?>[] { IntField.class, StringField.class, IntField.class,
                        IntField.class, IntField.class, StringField.class },
                new String[] { "pc", "op", "gas", "gasCost", "depth", "stack" });
        private final Table tbl;

        StructLogAdapter(DBHandle h, boolean create) throws IOException {
            tbl = create ? h.createTable("StructLogs", SCHEMA)
                    : h.getTable("StructLogs");
        }

        void put(Map<String, Object> log) throws IOException {
            DBRecord r = SCHEMA.createRecord(tbl.getKey());
            r.setIntValue(0, ((Number) log.get("pc")).intValue());
            r.setString(1, (String) log.get("op"));
            r.setIntValue(2, ((Number) log.get("gas")).intValue());
            r.setIntValue(3, ((Number) log.get("gasCost")).intValue());
            r.setIntValue(4, ((Number) log.get("depth")).intValue());

            try {
                r.setString(5, JSON.writeValueAsString(log.get("stack")));
            } catch (JsonProcessingException e) {
                r.setString(5, "[]");
            }
            tbl.putRecord(r);
        }
    }

    private void storeStructLogs(ProgramDB prog,
            List<Map<String, Object>> logs, TaskMonitor mon)
            throws IOException, CancelledException {
        DBHandle db = prog.getDBHandle();
        int tx = prog.startTransaction("StructLogs");
        try {
            StructLogAdapter adapter = new StructLogAdapter(db, db.getTable("StructLogs") == null);
            int total = logs.size();
            for (int i = 0; i < total; i++) {
                if (i % 1000 == 0) {
                    if (mon.isCancelled()) {
                        throw new CancelledException();
                    }
                    mon.setMessage("Storing struct logs: " + i + "/" + total);
                }
                adapter.put(logs.get(i));
            }
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    private void storeCallTracerData(ProgramDB prog, Map<String, Object> callTraceData) throws IOException {
        DBHandle db = prog.getDBHandle();
        int tx = prog.startTransaction("CallTracer");
        try {
            CallTracerAdapter adapter = new CallTracerAdapter(db, db.getTable("CallTracer") == null);
            adapter.put(callTraceData);
        } finally {
            prog.endTransaction(tx, true);
        }
    }

    private static class CallTracerAdapter {
        private static final int VER = 1;
        private static final Schema SCHEMA = new Schema(VER, "ID",
                new Class<?>[] { StringField.class, StringField.class, StringField.class,
                        StringField.class, StringField.class, StringField.class, StringField.class },
                new String[] { "from", "to", "type", "gas", "gasUsed", "value", "calls" });
        private final Table tbl;

        CallTracerAdapter(DBHandle h, boolean create) throws IOException {
            tbl = create ? h.createTable("CallTracer", SCHEMA)
                    : h.getTable("CallTracer");
        }

        void put(Map<String, Object> callTraceData) throws IOException {
            // Store the root call trace
            storeCallTrace(callTraceData, null);
        }

        private void storeCallTrace(Map<String, Object> callTrace, String parentId) throws IOException {
            DBRecord r = SCHEMA.createRecord(tbl.getKey());

            String from = (String) callTrace.get("from");
            String to = (String) callTrace.get("to");
            String type = (String) callTrace.get("type");
            String gas = callTrace.get("gas") != null ? callTrace.get("gas").toString() : "0";
            String gasUsed = callTrace.get("gasUsed") != null ? callTrace.get("gasUsed").toString() : "0";
            String value = callTrace.get("value") != null ? callTrace.get("value").toString() : "0x0";

            r.setString(0, from != null ? from : "");
            r.setString(1, to != null ? to : "");
            r.setString(2, type != null ? type : "CALL");
            r.setString(3, gas);
            r.setString(4, gasUsed);
            r.setString(5, value);

            // Store nested calls as JSON
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> calls = (List<Map<String, Object>>) callTrace.get("calls");
            if (calls != null && !calls.isEmpty()) {
                try {
                    String callsJson = JSON.writeValueAsString(calls);
                    r.setString(6, callsJson);
                } catch (JsonProcessingException e) {
                    r.setString(6, "[]");
                }
            } else {
                r.setString(6, "[]");
            }

            tbl.putRecord(r);

            // Recursively store nested calls
            if (calls != null) {
                for (Map<String, Object> nestedCall : calls) {
                    storeCallTrace(nestedCall, String.valueOf(r.getKey()));
                }
            }
        }
    }

    private static class ContractInfoAdapter {
        private static final int VER = 1;
        private static final Schema SCHEMA = new Schema(VER, "ID",
                new Class<?>[] { StringField.class, LongField.class, StringField.class },
                new String[] { "contractAddress", "baseOffset", "memoryBlockName" });
        private final Table tbl;

        ContractInfoAdapter(DBHandle h, boolean create) throws IOException {
            tbl = create ? h.createTable("ContractInfo", SCHEMA)
                    : h.getTable("ContractInfo");
        }

        void put(String contractAddress, long baseOffset, String memoryBlockName) throws IOException {
            MothraLog.debug(this, "=== DEBUG: ContractInfoAdapter.put called ===");
            DBRecord r = SCHEMA.createRecord(tbl.getKey());
            r.setString(0, contractAddress);
            r.setLongValue(1, baseOffset);
            r.setString(2, memoryBlockName);
            tbl.putRecord(r);
            MothraLog.debug(this, 
                    "=== DEBUG: Record added to table, table now has " + tbl.getRecordCount() + " records ===");
        }

    }

    private void storeContractInfo(ProgramDB prog, String contractAddress, long baseOffset, MessageLog log) {
        MothraLog.debug(this, 
                "=== DEBUG: storeContractInfo called for " + contractAddress + " at offset " + baseOffset + " ===");
        try {
            DBHandle db = prog.getDBHandle();
            int tx = prog.startTransaction("ContractInfo");
            try {
                ContractInfoAdapter adapter = new ContractInfoAdapter(db, db.getTable("ContractInfo") == null);
                String memoryBlockName = formatContractName(contractAddress);

                MothraLog.debug(this, "=== DEBUG: About to store record in ContractInfo table ===");
                adapter.put(contractAddress, baseOffset, memoryBlockName);
                MothraLog.debug(this, "=== DEBUG: Record stored successfully ===");

            } finally {
                prog.endTransaction(tx, true);
                MothraLog.debug(this, "=== DEBUG: Transaction committed ===");
            }
        } catch (IOException e) {
            MothraLog.error(this, "=== DEBUG: Exception in storeContractInfo: " + e.getMessage() + " ===");
            log.appendException(e);
            log.appendMsg("Failed to store contract info for " + contractAddress);
        }
    }

    private static String formatContractName(String contractAddress) {
        if (contractAddress == null || contractAddress.length() < 10) {
            return contractAddress;
        }

        String cleanAddress = strip0x(contractAddress);
        if (cleanAddress.length() < 8) {
            return contractAddress;
        }

        String first4bytes = cleanAddress.substring(0, 4);
        String last4bytes = cleanAddress.substring(cleanAddress.length() - 4);
        return "0x" + first4bytes + "..." + last4bytes;
    }

    private static String ensure0x(String s) {
        return s.startsWith("0x") ? s : "0x" + s;
    }

    private static String strip0x(String s) {
        return s.startsWith("0x") ? s.substring(2) : s;
    }

    private static byte[] hexToBytes(String s) {
        s = strip0x(s);
        if ((s.length() & 1) == 1)
            s = "0" + s;
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2)
            out[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        return out;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder builder = new StringBuilder(b.length * 2);
        for (byte x : b)
            builder.append(String.format("%02x", x));
        return builder.toString();
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider p, LoadSpec l,
            DomainObject d, boolean inProg, boolean mirrorFsLayout) {
        return super.getDefaultOptions(p, l, d, inProg, mirrorFsLayout);
    }

    @Override
    public String validateOptions(ByteProvider p, LoadSpec l,
            List<Option> o, Program prog) {
        return super.validateOptions(p, l, o, prog);
    }
}