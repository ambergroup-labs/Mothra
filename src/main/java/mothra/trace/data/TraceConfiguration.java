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

/**
 * Configuration for trace generation
 *
 * Holds settings for RPC endpoint, caching, and Ghidra language
 */
public class TraceConfiguration {
    private String rpcUrl;
    private String languageId;
    private String cacheDirectory;

    /**
     * Constructor with default values
     */
    public TraceConfiguration() {
        // Defaults
        this.rpcUrl = "http://localhost:8545";
        this.languageId = "evm:256:default";
        this.cacheDirectory = "/tmp/eth-trace-cache";
    }

    // Getters and setters
    public String getRpcUrl() {
        return rpcUrl;
    }

    public void setRpcUrl(String rpcUrl) {
        this.rpcUrl = rpcUrl;
    }

    public String getLanguageId() {
        return languageId;
    }

    public void setLanguageId(String languageId) {
        this.languageId = languageId;
    }

    public String getCacheDirectory() {
        return cacheDirectory;
    }

    public void setCacheDirectory(String cacheDirectory) {
        this.cacheDirectory = cacheDirectory;
    }
}
