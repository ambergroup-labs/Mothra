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
package mothra.util;

import ghidra.util.Msg;

/**
 * Centralized logging utility for Mothra plugin
 *
 * Provides consistent logging with [Mothra] prefix and proper severity levels.
 * All logs are written to Ghidra's application.log file.
 */
public class MothraLog {

    private static final String PREFIX = "[Mothra] ";

    /**
     * Log informational message
     * @param origin The calling object (typically 'this')
     * @param message The message to log
     */
    public static void info(Object origin, String message) {
        Msg.info(origin, PREFIX + message);
    }

    /**
     * Log warning message
     * @param origin The calling object (typically 'this')
     * @param message The warning message
     */
    public static void warn(Object origin, String message) {
        Msg.warn(origin, PREFIX + message);
    }

    /**
     * Log error message
     * @param origin The calling object (typically 'this')
     * @param message The error message
     */
    public static void error(Object origin, String message) {
        Msg.error(origin, PREFIX + message);
    }

    /**
     * Log error message with exception
     * @param origin The calling object (typically 'this')
     * @param message The error message
     * @param t The throwable/exception
     */
    public static void error(Object origin, String message, Throwable t) {
        Msg.error(origin, PREFIX + message, t);
    }

    /**
     * Log debug message (only shown if debug logging is enabled)
     * @param origin The calling object (typically 'this')
     * @param message The debug message
     */
    public static void debug(Object origin, String message) {
        Msg.debug(origin, PREFIX + message);
    }

    /**
     * Log progress message for long-running operations
     * @param origin The calling object (typically 'this')
     * @param message The progress message
     */
    public static void progress(Object origin, String message) {
        Msg.info(origin, PREFIX + "[Progress] " + message);
    }
}
