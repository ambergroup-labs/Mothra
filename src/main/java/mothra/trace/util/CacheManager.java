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
package mothra.trace.util;

import java.io.*;
import java.nio.file.*;
import mothra.util.MothraLog;

/**
 * CacheManager - Manages caching of Ethereum data in /tmp directory
 *
 * Caches:
 * - Call traces by transaction hash
 * - Instruction traces by transaction hash
 * - Contract bytecode by address
 *
 * This avoids repeated RPC calls for the same data.
 */
public class CacheManager {

    private static final String CACHE_DIR =
            Paths.get(System.getProperty("java.io.tmpdir"), "eth-trace-cache").toString();
    private static final String CALL_TRACE_DIR = Paths.get(CACHE_DIR, "call-traces").toString();
    private static final String INSTRUCTION_TRACE_DIR = Paths.get(CACHE_DIR, "instruction-traces").toString();
    private static final String BYTECODE_DIR = Paths.get(CACHE_DIR, "bytecode").toString();

    /**
     * Initialize cache directories
     */
    public static void initialize() throws IOException {
        Files.createDirectories(Paths.get(CALL_TRACE_DIR));
        Files.createDirectories(Paths.get(INSTRUCTION_TRACE_DIR));
        Files.createDirectories(Paths.get(BYTECODE_DIR));
    }

    /**
     * Get cached call trace for a transaction hash
     *
     * @param txHash Transaction hash (with or without 0x prefix)
     * @return JSON string of call trace, or null if not cached
     */
    public static String getCachedCallTrace(String txHash) {
        return readCache(CALL_TRACE_DIR, sanitizeTxHash(txHash));
    }

    /**
     * Cache call trace for a transaction hash
     *
     * @param txHash Transaction hash (with or without 0x prefix)
     * @param jsonData JSON string of call trace
     */
    public static void cacheCallTrace(String txHash, String jsonData) throws IOException {
        writeCache(CALL_TRACE_DIR, sanitizeTxHash(txHash), jsonData);
    }

    /**
     * Get cached instruction trace for a transaction hash
     *
     * @param txHash Transaction hash (with or without 0x prefix)
     * @return JSON string of instruction trace, or null if not cached
     */
    public static String getCachedInstructionTrace(String txHash) {
        return readCache(INSTRUCTION_TRACE_DIR, sanitizeTxHash(txHash));
    }

    /**
     * Cache instruction trace for a transaction hash
     *
     * @param txHash Transaction hash (with or without 0x prefix)
     * @param jsonData JSON string of instruction trace
     */
    public static void cacheInstructionTrace(String txHash, String jsonData) throws IOException {
        writeCache(INSTRUCTION_TRACE_DIR, sanitizeTxHash(txHash), jsonData);
    }

    /**
     * Get cached bytecode for a contract address
     *
     * @param address Contract address (with or without 0x prefix)
     * @return Hex string of bytecode (without 0x prefix), or null if not cached
     */
    public static String getCachedBytecode(String address) {
        return readCache(BYTECODE_DIR, sanitizeAddress(address));
    }

    /**
     * Cache bytecode for a contract address
     *
     * @param address Contract address (with or without 0x prefix)
     * @param bytecode Hex string of bytecode (with or without 0x prefix)
     */
    public static void cacheBytecode(String address, String bytecode) throws IOException {
        writeCache(BYTECODE_DIR, sanitizeAddress(address), sanitizeHex(bytecode));
    }

    /**
     * Sanitize transaction hash - remove 0x prefix and convert to lowercase
     */
    private static String sanitizeTxHash(String txHash) {
        if (txHash == null) return null;
        String clean = txHash.toLowerCase();
        if (clean.startsWith("0x")) {
            clean = clean.substring(2);
        }
        return clean;
    }

    /**
     * Sanitize address - remove 0x prefix and convert to lowercase
     */
    private static String sanitizeAddress(String address) {
        if (address == null) return null;
        String clean = address.toLowerCase();
        if (clean.startsWith("0x")) {
            clean = clean.substring(2);
        }
        return clean;
    }

    /**
     * Sanitize hex string - remove 0x prefix
     */
    private static String sanitizeHex(String hex) {
        if (hex == null) return null;
        if (hex.startsWith("0x") || hex.startsWith("0X")) {
            return hex.substring(2);
        }
        return hex;
    }

    /**
     * Read from cache
     *
     * @param directory Cache directory
     * @param key Cache key (filename)
     * @return Cached data, or null if not found
     */
    private static String readCache(String directory, String key) {
        if (key == null) return null;

        Path filePath = Paths.get(directory, key + ".cache");
        if (!Files.exists(filePath)) {
            return null;
        }

        try {
            return Files.readString(filePath);
        } catch (IOException e) {
            MothraLog.warn(CacheManager.class, "Failed to read cache file: " + filePath);
            return null;
        }
    }

    /**
     * Write to cache
     *
     * @param directory Cache directory
     * @param key Cache key (filename)
     * @param data Data to cache
     */
    private static void writeCache(String directory, String key, String data) throws IOException {
        if (key == null || data == null) return;

        Path filePath = Paths.get(directory, key + ".cache");
        Files.writeString(filePath, data);
    }

    /**
     * Clear all caches
     */
    public static void clearAllCaches() throws IOException {
        deleteDirectory(Paths.get(CACHE_DIR));
        initialize();
    }

    /**
     * Clear call trace cache
     */
    public static void clearCallTraceCache() throws IOException {
        deleteDirectory(Paths.get(CALL_TRACE_DIR));
        Files.createDirectories(Paths.get(CALL_TRACE_DIR));
    }

    /**
     * Clear instruction trace cache
     */
    public static void clearInstructionTraceCache() throws IOException {
        deleteDirectory(Paths.get(INSTRUCTION_TRACE_DIR));
        Files.createDirectories(Paths.get(INSTRUCTION_TRACE_DIR));
    }

    /**
     * Clear bytecode cache
     */
    public static void clearBytecodeCache() throws IOException {
        deleteDirectory(Paths.get(BYTECODE_DIR));
        Files.createDirectories(Paths.get(BYTECODE_DIR));
    }

    /**
     * Delete directory recursively
     */
    private static void deleteDirectory(Path directory) throws IOException {
        if (!Files.exists(directory)) return;

        Files.walk(directory)
            .sorted((a, b) -> -a.compareTo(b))  // Reverse order to delete files before directories
            .forEach(path -> {
                try {
                    Files.delete(path);
                } catch (IOException e) {
                    MothraLog.warn(CacheManager.class, "Failed to delete cache: " + path);
                }
            });
    }
}
