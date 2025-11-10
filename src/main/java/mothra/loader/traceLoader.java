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
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import ghidra.util.Msg;

public class traceLoader extends AbstractProgramWrapperLoader {

    private static final String RPC_URL = "https://home.sui.fund:8443/rpc/d712135b-47c1-4dab-ad0a-1570fb8661fe";
    private static final OkHttpClient CLIENT = new OkHttpClient();
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final MediaType JSON_MEDIA = MediaType.parse("application/json; charset=utf-8");

    private static final long CONTRACT_SPACING = 0x10000L;

    private static class ContractData {
        final String contractAddress, contractCode;

        ContractData(String address, String code) {
            contractAddress = address;
            contractCode = code;
        }
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
    protected void load(ByteProvider provider, LoadSpec spec, List<Option> opts,
            Program program, TaskMonitor mon, MessageLog log)
            throws CancelledException, IOException {

        FlatProgramAPI api = new FlatProgramAPI(program, mon);
        byte[] hashBytes = provider.readBytes(0, provider.length());

        String txHash = ensure0x(bytesToHex(hashBytes));

        List<ContractData> contracts = fetchContracts(txHash);
        System.out.println("=== DEBUG: fetchContracts returned " + contracts.size() + " contracts ===");

        mon.initialize(contracts.size() + 1);

        long offset = 0;
        for (ContractData c : contracts) {
            if (mon.isCancelled())
                throw new CancelledException();

            System.out.println("=== DEBUG: Processing contract " + c.contractAddress + " at offset " + offset + " ===");
            loadContract(api, program, c.contractAddress, hexToBytes(strip0x(c.contractCode)),
                    offset, log);

            mon.incrementProgress(1);

            System.out.println("=== DEBUG: About to store contract info for " + c.contractAddress + " ===");
            storeContractInfo((ProgramDB) program, c.contractAddress, offset, log);
            System.out.println("=== DEBUG: Contract info stored successfully ===");
            offset += CONTRACT_SPACING;
        }

        List<Map<String, Object>> logsList = fetchStructLogs(txHash);
        storeStructLogs((ProgramDB) program, logsList);

        // Also store call tracer data
        Map<String, Object> callTraceData = fetchCallTracerData(txHash);
        if (callTraceData != null) {
            storeCallTracerData((ProgramDB) program, callTraceData);
        }
        mon.incrementProgress(1);
        mon.setMessage("TraceLoader: done.");
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
        api.addEntryPoint(addr);

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

    private Map<String, Object> rpc(String method, Object params) throws IOException {
        Map<String, Object> req = Map.of("jsonrpc", "2.0", "id", 1,
                "method", method, "params", params);

        RequestBody b = RequestBody.create(JSON.writeValueAsString(req), JSON_MEDIA);
        Request r = new Request.Builder().url(RPC_URL).post(b).build();

        try (Response res = CLIENT.newCall(r).execute()) {
            if (!res.isSuccessful()) {
                String errorBody = res.body() != null ? res.body().string() : "No response body";
                System.err.println("ERROR: RPC call failed with HTTP " + res.code() + ": " + errorBody);
                throw new IOException(method + " HTTP " + res.code() + ": " + errorBody);
            }

            String responseBody = res.body().string();
            Map<String, Object> result = JSON.readValue(responseBody, Map.class);
            return result;
        }
    }

    private List<ContractData> fetchContracts(String txHash) throws IOException {
        Map<String, Object> callTrace = rpc("debug_traceTransaction",
                List.of(txHash, Map.of("tracer", "callTracer")));

        if (callTrace == null || !callTrace.containsKey("result")) {
            System.err.println("ERROR: callTrace is null or missing 'result' field");
            throw new IOException("Failed to fetch call trace data for transaction: " + txHash);
        }

        Map<String, Object> result = (Map<String, Object>) callTrace.get("result");
        if (result == null || !result.containsKey("to")) {
            System.err.println("ERROR: result is null or missing 'to' field");
            throw new IOException("Invalid call trace result for transaction: " + txHash);
        }

        String rootAddr = result.get("to").toString().toLowerCase();

        Map<String, Object> prestateTrace = rpc("debug_traceTransaction",
                List.of(txHash, Map.of("tracer", "prestateTracer")));

        if (prestateTrace == null || !prestateTrace.containsKey("result")) {
            System.err.println("ERROR: prestateTrace is null or missing 'result' field");
            throw new IOException("Failed to fetch prestate trace data for transaction: " + txHash);
        }

        Map<String, Object> accounts = (Map<String, Object>) prestateTrace.get("result");

        List<ContractData> contracts = new ArrayList<>();
        System.out.println("=== DEBUG: Processing " + accounts.size() + " accounts from prestateTracer ===");
        for (var entry : accounts.entrySet()) {
            String addr = entry.getKey().toLowerCase();
            Map<String, Object> account = (Map<String, Object>) entry.getValue();
            String code = (String) account.get("code");

            System.out.println("=== DEBUG: Account " + addr + " has code length: "
                    + (code != null ? code.length() : "null") + " ===");

            if (code != null && !code.equals("0x") && !code.isEmpty()) {
                System.out
                        .println("=== DEBUG: Adding contract " + addr + " with code length " + code.length() + " ===");
                contracts.add(new ContractData(addr, code));
            }
        }

        System.out.println("=== DEBUG: Found " + contracts.size() + " contracts with code ===");
        contracts.sort((a, b) -> a.contractAddress.equals(rootAddr) ? -1 : b.contractAddress.equals(rootAddr) ? 1 : 0);
        return contracts;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> fetchStructLogs(String txHash) throws IOException {
        Map<String, Object> trace = rpc("debug_traceTransaction",
                List.of(txHash, Collections.emptyMap()));
        return (List<Map<String, Object>>) ((Map<String, Object>) trace.get("result")).getOrDefault("structLogs",
                List.of());
    }

    private Map<String, Object> fetchCallTracerData(String txHash) throws IOException {
        Map<String, Object> callTrace = rpc("debug_traceTransaction",
                List.of(txHash, Map.of("tracer", "callTracer")));

        if (callTrace == null || !callTrace.containsKey("result")) {
            System.err.println("ERROR: callTracer is null or missing 'result' field");
            return null;
        }

        return (Map<String, Object>) callTrace.get("result");
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
            List<Map<String, Object>> logs) throws IOException {
        DBHandle db = prog.getDBHandle();
        int tx = prog.startTransaction("StructLogs");
        try {
            StructLogAdapter adapter = new StructLogAdapter(db, db.getTable("StructLogs") == null);
            for (Map<String, Object> log : logs) {
                adapter.put(log);
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
            System.out.println("=== DEBUG: ContractInfoAdapter.put called ===");
            DBRecord r = SCHEMA.createRecord(tbl.getKey());
            r.setString(0, contractAddress);
            r.setLongValue(1, baseOffset);
            r.setString(2, memoryBlockName);
            tbl.putRecord(r);
            System.out.println(
                    "=== DEBUG: Record added to table, table now has " + tbl.getRecordCount() + " records ===");
        }

    }

    private void storeContractInfo(ProgramDB prog, String contractAddress, long baseOffset, MessageLog log) {
        System.out.println(
                "=== DEBUG: storeContractInfo called for " + contractAddress + " at offset " + baseOffset + " ===");
        try {
            DBHandle db = prog.getDBHandle();
            int tx = prog.startTransaction("ContractInfo");
            try {
                ContractInfoAdapter adapter = new ContractInfoAdapter(db, db.getTable("ContractInfo") == null);
                String memoryBlockName = formatContractName(contractAddress);

                System.out.println("=== DEBUG: About to store record in ContractInfo table ===");
                adapter.put(contractAddress, baseOffset, memoryBlockName);
                System.out.println("=== DEBUG: Record stored successfully ===");

            } finally {
                prog.endTransaction(tx, true);
                System.out.println("=== DEBUG: Transaction committed ===");
            }
        } catch (IOException e) {
            System.err.println("=== DEBUG: Exception in storeContractInfo: " + e.getMessage() + " ===");
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
            DomainObject d, boolean inProg) {
        return super.getDefaultOptions(p, l, d, inProg);
    }

    @Override
    public String validateOptions(ByteProvider p, LoadSpec l,
            List<Option> o, Program prog) {
        return super.validateOptions(p, l, o, prog);
    }
}