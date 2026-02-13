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
package mothra.trace.rpc;

import mothra.util.MothraLog;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;

import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import mothra.trace.util.CacheManager;

/**
 * EthereumRpcClient - Client for Ethereum JSON-RPC API
 *
 * Fetches:
 * - Call traces using debug_traceTransaction
 * - Instruction traces using debug_traceTransaction
 * - Contract bytecode using eth_getCode
 *
 * Integrates with CacheManager to avoid repeated RPC calls.
 */
public class EthereumRpcClient {

    private static final int CONNECT_TIMEOUT_MS = 30_000;  // 30 seconds
    private static final int READ_TIMEOUT_MS = 600_000;    // 10 minutes (traces can be large)

    private final String rpcUrl;
    private final Gson gson;
    private int requestId;

    /**
     * Create a new Ethereum RPC client
     *
     * @param rpcUrl URL of the Ethereum RPC endpoint
     */
    public EthereumRpcClient(String rpcUrl) {
        this.rpcUrl = rpcUrl;
        this.gson = new GsonBuilder().setPrettyPrinting().create();
        this.requestId = 1;
    }

    /**
     * Fetch call trace for a transaction
     *
     * Uses debug_traceTransaction with callTracer to get contract call hierarchy.
     * Results are cached in /tmp.
     *
     * @param txHash Transaction hash
     * @return JSON string of call trace
     */
    public String getCallTrace(String txHash) throws IOException, CancelledException {
        return getCallTrace(txHash, TaskMonitor.DUMMY);
    }

    public String getCallTrace(String txHash, TaskMonitor monitor) throws IOException, CancelledException {
        MothraLog.info(this, "[RPC] Fetching call trace for tx: " + txHash);

        // Check cache first
        String cached = CacheManager.getCachedCallTrace(txHash);
        if (cached != null) {
            MothraLog.info(this, "  ✓ Found in cache");
            return cached;
        }

        // Fetch from RPC
        MothraLog.info(this, "  → Calling debug_traceTransaction with callTracer...");
        JsonObject params = new JsonObject();
        params.addProperty("tracer", "callTracer");

        String result = callRpc(monitor, "debug_traceTransaction", txHash, params);

        // Cache the result
        CacheManager.cacheCallTrace(txHash, result);
        MothraLog.info(this, "  ✓ Fetched and cached");

        return result;
    }

    /**
     * Fetch instruction trace for a transaction
     *
     * Uses debug_traceTransaction with opcodes enabled to get instruction-level trace.
     * Results are cached in /tmp.
     *
     * @param txHash Transaction hash
     * @return JSON string of instruction trace
     */
    public String getInstructionTrace(String txHash) throws IOException, CancelledException {
        return getInstructionTrace(txHash, TaskMonitor.DUMMY);
    }

    public String getInstructionTrace(String txHash, TaskMonitor monitor) throws IOException, CancelledException {
        MothraLog.info(this, "[RPC] Fetching instruction trace for tx: " + txHash);

        // Check cache first
        String cached = CacheManager.getCachedInstructionTrace(txHash);
        if (cached != null) {
            MothraLog.info(this, "  ✓ Found in cache");
            return cached;
        }

        // Fetch from RPC
        MothraLog.info(this, "  → Calling debug_traceTransaction with structured logs...");
        JsonObject params = new JsonObject();
        // Use both old-style (disable*) and new-style (enable*) parameters for compatibility
        // Old style (Geth pre-1.11): disableXxx = false means enable
        params.addProperty("disableStorage", false);
        params.addProperty("disableMemory", false);
        params.addProperty("disableStack", false);
        // New style (Geth 1.11+, Erigon, etc.): enableXxx = true means enable
        params.addProperty("enableMemory", true);
        params.addProperty("enableReturnData", true);

        String result = callRpc(monitor, "debug_traceTransaction", txHash, params);

        // Cache the result
        CacheManager.cacheInstructionTrace(txHash, result);
        MothraLog.info(this, "  ✓ Fetched and cached");

        return result;
    }

    /**
     * Fetch contract bytecode at a given address
     *
     * Uses eth_getCode. Results are cached in /tmp by address.
     *
     * @param address Contract address
     * @param blockNumber Block number ("latest", "earliest", or hex number)
     * @return Hex string of bytecode (without 0x prefix)
     */
    public String getBytecode(String address, String blockNumber) throws IOException, CancelledException {
        return getBytecode(address, blockNumber, TaskMonitor.DUMMY);
    }

    public String getBytecode(String address, String blockNumber, TaskMonitor monitor)
            throws IOException, CancelledException {
        MothraLog.info(this, "[RPC] Fetching bytecode for address: " + address);

        // Check cache first
        String cached = CacheManager.getCachedBytecode(address);
        if (cached != null) {
            MothraLog.info(this, "  ✓ Found in cache");
            return cached;
        }

        // Fetch from RPC
        MothraLog.info(this, "  → Calling eth_getCode...");
        String result = callRpc(monitor, "eth_getCode", address, blockNumber);

        // Parse result and remove 0x prefix
        JsonObject resultObj = JsonParser.parseString(result).getAsJsonObject();
        String bytecode = resultObj.get("result").getAsString();
        if (bytecode.startsWith("0x")) {
            bytecode = bytecode.substring(2);
        }

        // Cache the result
        CacheManager.cacheBytecode(address, bytecode);
        MothraLog.info(this, "  ✓ Fetched and cached (" + bytecode.length() / 2 + " bytes)");

        return bytecode;
    }

    /**
     * Fetch contract bytecode at a given address (defaults to "latest" block)
     */
    public String getBytecode(String address) throws IOException, CancelledException {
        return getBytecode(address, "latest");
    }

    public String getBytecode(String address, TaskMonitor monitor) throws IOException, CancelledException {
        return getBytecode(address, "latest", monitor);
    }

    /**
     * Make a JSON-RPC call with variable parameters
     *
     * @param method RPC method name
     * @param params RPC parameters
     * @return JSON string response
     */
    private String callRpc(TaskMonitor monitor, String method, Object... params)
            throws IOException, CancelledException {
        // Check before starting
        if (monitor.isCancelled()) {
            throw new CancelledException();
        }

        // Build JSON-RPC request
        JsonObject request = new JsonObject();
        request.addProperty("jsonrpc", "2.0");
        request.addProperty("method", method);
        request.addProperty("id", requestId++);

        // Add parameters as JSON array
        JsonArray paramsArray = new JsonArray();
        for (Object param : params) {
            if (param instanceof String) {
                paramsArray.add((String) param);
            } else if (param instanceof Number) {
                paramsArray.add((Number) param);
            } else if (param instanceof Boolean) {
                paramsArray.add((Boolean) param);
            } else if (param instanceof JsonElement) {
                paramsArray.add((JsonElement) param);
            } else {
                paramsArray.add(gson.toJsonTree(param));
            }
        }
        request.add("params", paramsArray);

        // Send HTTP POST request
        String requestBody = gson.toJson(request);
        String response = sendHttpPost(rpcUrl, requestBody, monitor);

        // Check after completion
        if (monitor.isCancelled()) {
            throw new CancelledException();
        }

        // Check for errors
        JsonObject responseObj = JsonParser.parseString(response).getAsJsonObject();
        if (responseObj.has("error")) {
            JsonObject error = responseObj.getAsJsonObject("error");
            throw new IOException("RPC Error: " + error.get("message").getAsString());
        }

        return response;
    }

    /**
     * Send HTTP POST request with cancellation support.
     * Registers a CancelledListener that disconnects the HTTP connection
     * when the user clicks Cancel, immediately aborting blocking I/O.
     */
    private String sendHttpPost(String url, String body, TaskMonitor monitor)
            throws IOException, CancelledException {
        HttpURLConnection conn = null;
        try {
            URL urlObj = new URL(url);
            conn = (HttpURLConnection) urlObj.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);

            // Register a listener that disconnects the connection on cancel.
            // This causes any blocking read/write to throw IOException immediately.
            final HttpURLConnection connRef = conn;
            CancelledListener cancelListener = () -> {
                try {
                    connRef.disconnect();
                } catch (Exception ignored) {
                    // best-effort disconnect
                }
            };
            monitor.addCancelledListener(cancelListener);

            try {
                // Write request body
                try (OutputStream os = conn.getOutputStream()) {
                    byte[] input = body.getBytes(StandardCharsets.UTF_8);
                    os.write(input, 0, input.length);
                }

                // Read response
                int responseCode = conn.getResponseCode();
                InputStream inputStream = (responseCode < 400)
                        ? conn.getInputStream() : conn.getErrorStream();

                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = br.readLine()) != null) {
                        response.append(line);
                    }
                    return response.toString();
                }
            } catch (SocketException | SocketTimeoutException e) {
                // If cancelled, convert to CancelledException
                if (monitor.isCancelled()) {
                    throw new CancelledException();
                }
                throw e;
            } finally {
                monitor.removeCancelledListener(cancelListener);
            }
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    /**
     * Test connection to RPC endpoint
     */
    public boolean testConnection() {
        try {
            callRpc(TaskMonitor.DUMMY, "eth_blockNumber");
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
