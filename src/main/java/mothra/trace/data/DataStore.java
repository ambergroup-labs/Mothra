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
package mothra.trace.data;

import java.io.IOException;
import java.util.*;
import com.google.gson.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import mothra.trace.rpc.EthereumRpcClient;
import mothra.util.MothraLog;

/**
 * DataStore - Centralized storage for RPC data and processed results
 *
 * This class stores:
 * 1. Raw data from RPC (callTracer, structLog)
 * 2. Processed data structures derived from raw data
 *
 * Design follows REFACTOR_PART1.md specification
 */
public class DataStore {

    /**
     * Represents a single instruction execution step
     */
    public static class InstructionStep {
        public long pc;              // Program counter
        public int depth;            // Call depth
        public String op;            // Opcode name (PUSH1, ADD, etc.)
        public long gas;             // Gas remaining
        public long gasCost;         // Gas cost of operation
        public List<String> stack;   // Stack state (top to bottom)
        public String memory;        // Memory state (hex)
        public Map<String, String> storage;  // Storage state

        public InstructionStep() {
            stack = new ArrayList<>();
            storage = new HashMap<>();
        }
    }

    /**
     * Represents a contract call in the execution sequence
     */
    public static class ContractCall {
        public String address;       // Contract address (normalized, without 0x prefix)
        public String callData;      // Call data (input field from call trace, with 0x prefix)

        public ContractCall(String address, String callData) {
            this.address = address;
            this.callData = callData;
        }
    }

    // ========================================
    // Raw Data (1.1)
    // ========================================

    /** Raw call tracer data (JSON string) */
    private String callTracerData;

    /** Parsed call tracer result (cached to avoid re-parsing) */
    private JsonObject parsedCallTraceResult;

    /** Raw struct log data (JSON string) - instruction trace */
    private String structLogData;

    // ========================================
    // Processed Data (1.2)
    // ========================================

    /**
     * Map: contract address -> bytecode
     * For contracts created in this transaction, bytecode includes constructor
     * For existing contracts, bytecode is runtime bytecode
     */
    private Map<String, String> contractBytecode;

    /**
     * Contract execution sequence (may contain duplicates)
     * Each entry contains contract address and call data
     * Example: [ContractCall(contract1, data1), ContractCall(contract2, data2), ...]
     */
    private List<ContractCall> contractExecutionSequence;

    /**
     * Unique contract list (no duplicates, order preserved from first appearance)
     */
    private List<String> contractList;

    /**
     * Map: contract address -> deployment address in code space
     * Example: contract0 -> 0x10000, contract1 -> 0x20000, etc.
     */
    private Map<String, Long> contractDeploymentAddresses;

    /**
     * List of instruction execution steps (parsed from structLog)
     */
    private List<InstructionStep> instructionSteps;

    /** Code address offset for each contract (64KB per contract) */
    private static final long CODE_ADDRESS_OFFSET = 0x10000L;

    /** Gson instance for JSON parsing */
    private final Gson gson;

    /**
     * Constructor
     */
    public DataStore() {
        this.contractBytecode = new LinkedHashMap<>();
        this.contractExecutionSequence = new ArrayList<>();
        this.contractList = new ArrayList<>();
        this.contractDeploymentAddresses = new LinkedHashMap<>();
        this.instructionSteps = new ArrayList<>();
        this.gson = new Gson();
    }

    // ========================================
    // Raw Data Access Methods
    // ========================================

    /**
     * Fetch all raw data from RPC node
     *
     * @param client RPC client
     * @param txHash Transaction hash
     */
    public void fetchRawData(EthereumRpcClient client, String txHash)
            throws IOException, CancelledException {
        fetchRawData(client, txHash, TaskMonitor.DUMMY);
    }

    /**
     * Fetch all raw data from RPC node with progress monitoring
     *
     * @param client RPC client
     * @param txHash Transaction hash
     * @param monitor Task monitor for progress reporting
     */
    public void fetchRawData(EthereumRpcClient client, String txHash, TaskMonitor monitor)
            throws IOException, CancelledException {
        MothraLog.progress(this, "  → Fetching call tracer data...");
        monitor.setMessage("Fetching call trace data...");
        this.callTracerData = client.getCallTrace(txHash, monitor);
        this.parsedCallTraceResult = null;  // Clear cached parsed result
        MothraLog.info(this, "    ✓ Call trace data fetched");

        if (monitor.isCancelled()) {
            throw new CancelledException();
        }

        MothraLog.progress(this, "  → Fetching struct log data...");
        monitor.setMessage("Fetching instruction trace data...");
        this.structLogData = client.getInstructionTrace(txHash, monitor);
        MothraLog.info(this, "    ✓ Struct log data fetched");
    }

    public String getCallTracerData() {
        return callTracerData;
    }

    public String getStructLogData() {
        return structLogData;
    }

    // ========================================
    // Data Processing Methods (1.2.1)
    // ========================================

    /**
     * Get parsed call trace result, parsing and caching if necessary
     * This avoids parsing callTracerData multiple times
     *
     * @return Parsed call trace result JsonObject
     * @throws Exception if call tracer data not fetched yet
     */
    private JsonObject getParsedCallTraceResult() throws Exception {
        if (callTracerData == null) {
            throw new Exception("Call tracer data not fetched yet");
        }

        if (parsedCallTraceResult == null) {
            JsonObject callTraceResponse = JsonParser.parseString(callTracerData).getAsJsonObject();
            parsedCallTraceResult = callTraceResponse.has("result") ?
                callTraceResponse.getAsJsonObject("result") : callTraceResponse;
        }

        return parsedCallTraceResult;
    }

    /**
     * Process contract bytecode from call trace data
     *
     * Handles two cases:
     * 1. Newly created contracts: Get constructor bytecode from CREATE/CREATE2 input
     * 2. Existing contracts: Get bytecode using eth_getCode
     *
     * Must be called AFTER processCallSequence() so contractList is populated
     *
     * @param client RPC client for fetching bytecode
     */
    public void processContractBytecode(EthereumRpcClient client) throws Exception {
        processContractBytecode(client, TaskMonitor.DUMMY);
    }

    public void processContractBytecode(EthereumRpcClient client, TaskMonitor monitor) throws Exception {
        MothraLog.progress(this, "  → Processing contract bytecode...");

        if (contractList.isEmpty()) {
            throw new Exception("Contract list is empty. Call processCallSequence() first.");
        }

        JsonObject callTraceResult = getParsedCallTraceResult();

        // First, identify contracts created in this transaction and extract constructor bytecode
        Map<String, String> createdContracts = new HashMap<>();
        extractCreatedContracts(callTraceResult, createdContracts);

        if (!createdContracts.isEmpty()) {
            MothraLog.info(this, "    → Found " + createdContracts.size() +
                             " newly created contract(s)");
            for (Map.Entry<String, String> entry : createdContracts.entrySet()) {
                MothraLog.info(this, "    ✓ Extracted constructor bytecode for " + entry.getKey() +
                                 " (" + (entry.getValue().length() / 2) + " bytes)");
            }
        }

        // Now fetch bytecode for all contracts in the list
        int fetchedCount = 0;
        int createdCount = 0;
        int skippedCount = 0;

        for (String address : contractList) {
            if (monitor.isCancelled()) {
                throw new CancelledException();
            }

            // Check if this contract was created in this transaction
            if (createdContracts.containsKey(address)) {
                // Use constructor bytecode from CREATE/CREATE2
                contractBytecode.put(address, createdContracts.get(address));
                createdCount++;
            } else {
                // Fetch bytecode using eth_getCode (runtime bytecode)
                String bytecode = client.getBytecode(address, monitor);
                if (bytecode != null && !bytecode.isEmpty()) {
                    // Add 0x prefix back if needed
                    if (!bytecode.startsWith("0x")) {
                        bytecode = "0x" + bytecode;
                    }
                    contractBytecode.put(address, bytecode);
                    fetchedCount++;
                } else {
                    // EOA or precompile
                    skippedCount++;
                }
            }
        }

        MothraLog.info(this, "    ✓ Used constructor bytecode for " + createdCount + " created contract(s)");
        MothraLog.info(this, "    ✓ Fetched runtime bytecode for " + fetchedCount + " existing contract(s)");
        MothraLog.info(this, "    ✓ Skipped " + skippedCount + " EOA/precompile address(es)");
        MothraLog.info(this, "    ✓ Total contracts with bytecode: " + contractBytecode.size());
    }

    /**
     * Extract created contracts and their constructor bytecode from call trace
     * Recursively searches for CREATE/CREATE2 calls and extracts input data
     *
     * @param callTraceResult Call trace JSON root
     * @param createdContracts Map to store created contract address -> constructor bytecode
     */
    private void extractCreatedContracts(JsonObject callTraceResult,
                                        Map<String, String> createdContracts) {
        extractCreatedContractsRecursive(callTraceResult, createdContracts);
    }

    /**
     * Recursively extract created contracts from call trace
     */
    private void extractCreatedContractsRecursive(JsonObject call,
                                                  Map<String, String> createdContracts) {
        // Check if this is a CREATE or CREATE2 call
        String type = call.has("type") ? call.get("type").getAsString() : "";
        if (type.equals("CREATE") || type.equals("CREATE2")) {
            String to = call.has("to") ? call.get("to").getAsString() : "";
            if (!to.isEmpty() && !to.equals("0x")) {
                String normalizedAddr = normalizeAddress(to);
                // Get the input data (constructor bytecode)
                String input = call.has("input") ? call.get("input").getAsString() : "";
                if (!input.isEmpty() && !input.equals("0x")) {
                    createdContracts.put(normalizedAddr, input);
                }
            }
        }

        // Recursively process nested calls
        if (call.has("calls")) {
            JsonArray calls = call.getAsJsonArray("calls");
            for (int i = 0; i < calls.size(); i++) {
                JsonElement callElement = calls.get(i);
                if (callElement.isJsonObject()) {
                    extractCreatedContractsRecursive(callElement.getAsJsonObject(),
                                                    createdContracts);
                }
            }
        }
    }

    // ========================================
    // Data Processing Methods (1.2.2)
    // ========================================

    /**
     * Process call sequence from call tracer data
     * Creates both the execution sequence and unique contract list
     */
    public void processCallSequence() throws Exception {
        MothraLog.progress(this, "  → Processing call sequence...");

        JsonObject callTraceResult = getParsedCallTraceResult();

        // Clear existing data
        contractExecutionSequence.clear();
        contractList.clear();
        Set<String> seenContracts = new LinkedHashSet<>();

        // Extract call sequence recursively (null for initial parent call data)
        extractCallSequence(callTraceResult, contractExecutionSequence, seenContracts, null);

        // Build unique contract list (preserve first appearance order)
        contractList.addAll(seenContracts);

        MothraLog.info(this, "    ✓ Execution sequence length: " +
                         contractExecutionSequence.size());
        MothraLog.info(this, "    ✓ Unique contracts: " + contractList.size());
    }

    /**
     * Recursively extract call sequence from call trace
     *
     * @param call Current call node
     * @param sequence List to accumulate execution sequence (with call data)
     * @param seen Set to track seen contracts
     * @param parentCallData Call data to use when returning to parent (null for initial call)
     */
    private void extractCallSequence(JsonObject call, List<ContractCall> sequence,
                                     Set<String> seen, String parentCallData) {
        // Get the 'to' address (contract being called)
        String to = call.has("to") ? call.get("to").getAsString() : "";
        // Get the 'input' field (call data)
        String input = call.has("input") ? call.get("input").getAsString() : "";

        if (!to.isEmpty() && !to.equals("0x")) {
            String normalizedAddr = normalizeAddress(to);

            // Add to sequence with call data (may have duplicates)
            sequence.add(new ContractCall(normalizedAddr, input));

            // Add to seen set (for unique list)
            seen.add(normalizedAddr);
        }

        // Recursively process nested calls
        if (call.has("calls")) {
            JsonArray calls = call.getAsJsonArray("calls");
            for (int i = 0; i < calls.size(); i++) {
                JsonElement callElement = calls.get(i);
                if (callElement.isJsonObject()) {
                    // Pass current input as parent call data for when we return
                    extractCallSequence(callElement.getAsJsonObject(), sequence, seen, input);

                    // When returning from nested call, add parent address again
                    // Use the original call data since we're returning to continue execution
                    if (!to.isEmpty() && !to.equals("0x")) {
                        String normalizedAddr = normalizeAddress(to);
                        sequence.add(new ContractCall(normalizedAddr, input));
                    }
                }
            }
        }
    }

    // ========================================
    // Data Processing Methods (1.2.3)
    // ========================================

    /**
     * Process instruction trace from struct log data
     * Parses the structLogs array and creates InstructionStep list
     */
    public void processInstructionTrace() throws Exception {
        MothraLog.progress(this, "  → Processing instruction trace...");

        if (structLogData == null) {
            throw new Exception("Struct log data not fetched yet");
        }

        instructionSteps.clear();

        JsonObject response = JsonParser.parseString(structLogData).getAsJsonObject();
        JsonObject result = response.has("result") ?
            response.getAsJsonObject("result") : response;

        // Get the structLogs array
        if (!result.has("structLogs")) {
            throw new Exception("No structLogs found in instruction trace data");
        }

        JsonArray structLogs = result.getAsJsonArray("structLogs");

        // Parse each log entry
        for (JsonElement logElement : structLogs) {
            JsonObject log = logElement.getAsJsonObject();

            InstructionStep step = new InstructionStep();

            // Extract PC
            step.pc = log.get("pc").getAsLong();

            // Extract opcode
            step.op = log.get("op").getAsString();

            // Extract gas
            step.gas = log.get("gas").getAsLong();

            // Extract gas cost
            if (log.has("gasCost")) {
                step.gasCost = log.get("gasCost").getAsLong();
            }

            // Extract depth
            step.depth = log.get("depth").getAsInt();

            // Extract stack (array of hex strings, top of stack is last element)
            if (log.has("stack")) {
                JsonArray stack = log.getAsJsonArray("stack");
                for (JsonElement stackElement : stack) {
                    step.stack.add(stackElement.getAsString());
                }
            }

            // Extract memory (hex string array or single hex string)
            if (log.has("memory")) {
                JsonElement memoryElement = log.get("memory");
                if (memoryElement.isJsonArray()) {
                    // Memory as array of 32-byte hex strings (common format)
                    JsonArray memory = memoryElement.getAsJsonArray();
                    StringBuilder memoryStr = new StringBuilder();
                    for (JsonElement memElement : memory) {
                        memoryStr.append(memElement.getAsString());
                    }
                    step.memory = memoryStr.toString();
                } else if (memoryElement.isJsonPrimitive()) {
                    // Memory as single hex string
                    step.memory = memoryElement.getAsString();
                    if (step.memory.startsWith("0x")) {
                        step.memory = step.memory.substring(2);
                    }
                }
                // Log first step's memory for debugging
                if (instructionSteps.isEmpty() && step.memory != null) {
                    MothraLog.debug(this, "  First step memory size: " + step.memory.length() / 2 + " bytes");
                }
            } else {
                // Log if memory is missing (first step only to avoid spam)
                if (instructionSteps.isEmpty()) {
                    MothraLog.debug(this, "  Warning: First step has no memory field in structLog");
                }
            }

            // Extract storage
            if (log.has("storage")) {
                JsonObject storage = log.getAsJsonObject("storage");
                for (Map.Entry<String, JsonElement> entry : storage.entrySet()) {
                    step.storage.put(entry.getKey(), entry.getValue().getAsString());
                }
            }

            instructionSteps.add(step);
        }

        MothraLog.info(this, "    ✓ Parsed " + instructionSteps.size() + " instruction steps");
    }

    // ========================================
    // Data Processing Methods (1.2.4)
    // ========================================

    /**
     * Assign deployment addresses to contracts
     * Each contract gets a 64KB space: 0x10000, 0x20000, 0x30000, ...
     */
    public void assignDeploymentAddresses() {
        MothraLog.progress(this, "  → Assigning deployment addresses...");

        contractDeploymentAddresses.clear();

        for (int i = 0; i < contractList.size(); i++) {
            String contract = contractList.get(i);
            long deploymentAddress = CODE_ADDRESS_OFFSET * i;
            contractDeploymentAddresses.put(contract, deploymentAddress);

            MothraLog.info(this, "    → Contract " + i + " (" + contract +
                             ") -> 0x" + Long.toHexString(deploymentAddress));
        }

        MothraLog.info(this, "    ✓ Assigned addresses to " + contractList.size() +
                         " contract(s)");
    }

    // ========================================
    // Processed Data Access Methods
    // ========================================

    public Map<String, String> getContractBytecode() {
        return Collections.unmodifiableMap(contractBytecode);
    }

    public List<ContractCall> getContractExecutionSequence() {
        return Collections.unmodifiableList(contractExecutionSequence);
    }

    public List<String> getContractList() {
        return Collections.unmodifiableList(contractList);
    }

    public Map<String, Long> getContractDeploymentAddresses() {
        return Collections.unmodifiableMap(contractDeploymentAddresses);
    }

    public List<InstructionStep> getInstructionSteps() {
        return Collections.unmodifiableList(instructionSteps);
    }

    /**
     * Get bytecode for a specific contract
     *
     * @param address Contract address
     * @return Bytecode hex string, or null if not found
     */
    public String getBytecode(String address) {
        return contractBytecode.get(normalizeAddress(address));
    }

    /**
     * Get deployment address for a specific contract
     *
     * @param address Contract address
     * @return Deployment address in code space, or null if not found
     */
    public Long getDeploymentAddress(String address) {
        return contractDeploymentAddresses.get(normalizeAddress(address));
    }

    // ========================================
    // Utility Methods
    // ========================================

    /**
     * Normalize address (lowercase, remove 0x prefix)
     */
    private String normalizeAddress(String address) {
        String normalized = address.toLowerCase();
        if (normalized.startsWith("0x")) {
            normalized = normalized.substring(2);
        }
        return normalized;
    }

    /**
     * Filter execution sequence and contract list to remove contracts without bytecode
     * Removes EOAs and precompiles from the sequences
     */
    private void filterContractsWithoutBytecode() {
        MothraLog.progress(this, "  → Filtering contracts without bytecode...");

        int originalSeqSize = contractExecutionSequence.size();
        int originalListSize = contractList.size();

        // Filter execution sequence - remove entries without bytecode
        List<ContractCall> filteredSequence = new ArrayList<>();
        for (ContractCall call : contractExecutionSequence) {
            if (contractBytecode.containsKey(call.address) &&
                contractBytecode.get(call.address) != null &&
                !contractBytecode.get(call.address).isEmpty()) {
                filteredSequence.add(call);
            }
        }
        contractExecutionSequence.clear();
        contractExecutionSequence.addAll(filteredSequence);

        // Filter contract list - remove entries without bytecode
        List<String> filteredList = new ArrayList<>();
        for (String address : contractList) {
            if (contractBytecode.containsKey(address) &&
                contractBytecode.get(address) != null &&
                !contractBytecode.get(address).isEmpty()) {
                filteredList.add(address);
            }
        }
        contractList.clear();
        contractList.addAll(filteredList);

        int removedFromSeq = originalSeqSize - contractExecutionSequence.size();
        int removedFromList = originalListSize - contractList.size();

        MothraLog.info(this, "    ✓ Removed " + removedFromSeq + " entries from execution sequence");
        MothraLog.info(this, "    ✓ Removed " + removedFromList + " contracts from contract list");
        MothraLog.info(this, "    ✓ Final execution sequence length: " + contractExecutionSequence.size());
        MothraLog.info(this, "    ✓ Final unique contracts: " + contractList.size());
    }

    /**
     * Complete data processing pipeline
     * Calls all processing methods in correct order
     *
     * @param client RPC client for additional queries if needed
     */
    public void processAllData(EthereumRpcClient client) throws Exception {
        processAllData(client, TaskMonitor.DUMMY);
    }

    /**
     * Complete data processing pipeline with progress monitoring
     * Calls all processing methods in correct order
     *
     * @param client RPC client for additional queries if needed
     * @param monitor Task monitor for progress reporting
     */
    public void processAllData(EthereumRpcClient client, TaskMonitor monitor) throws Exception {
        MothraLog.progress(this, "[Processing Data]");

        monitor.setMessage("Processing call sequence...");
        processCallSequence();              // Extract call sequence from callTracer

        if (monitor.isCancelled()) return;

        monitor.setMessage("Fetching contract bytecode...");
        processContractBytecode(client, monitor);  // Get bytecode (constructor or runtime)

        if (monitor.isCancelled()) return;

        monitor.setMessage("Filtering contracts...");
        filterContractsWithoutBytecode();   // Remove contracts without bytecode

        if (monitor.isCancelled()) return;

        monitor.setMessage("Processing instruction trace...");
        processInstructionTrace();          // Parse instruction steps from structLog

        if (monitor.isCancelled()) return;

        monitor.setMessage("Assigning deployment addresses...");
        assignDeploymentAddresses();        // Assign deployment addresses

        MothraLog.info(this, "  ✓ All data processed\n");
    }

    /**
     * Print summary of stored data
     */
    public void printSummary() {
        MothraLog.info(this, "DataStore Summary:");
        MothraLog.info(this, "  Raw Data:");
        MothraLog.info(this, "    CallTrace: " + (callTracerData != null ? "✓" : "✗"));
        MothraLog.info(this, "    StructLog: " + (structLogData != null ? "✓" : "✗"));
        MothraLog.info(this, "  Processed Data:");
        MothraLog.info(this, "    Contracts with bytecode: " + contractBytecode.size());
        MothraLog.info(this, "    Execution sequence length: " + contractExecutionSequence.size());
        MothraLog.info(this, "    Unique contracts: " + contractList.size());
        MothraLog.info(this, "    Instruction steps: " + instructionSteps.size());
        MothraLog.info(this, "    Deployment addresses: " + contractDeploymentAddresses.size());
    }
}
