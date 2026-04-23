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
package mothra.loader;

import java.awt.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.LinkedHashMap;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.trace.model.Trace;
import ghidra.trace.model.memory.TraceMemoryManager;
import ghidra.trace.model.memory.TraceMemoryState;
import mothra.util.MothraLog;

/**
 * EvmStateProvider - UI component for displaying EVM execution state
 *
 * Displays four panels:
 * - Calldata (0x40000000): Transaction input data
 * - Memory (0x50000000): EVM memory state
 * - Stack (0x60000000): EVM stack contents
 * - Storage (0x70000000): Contract storage key-value pairs
 *
 * Data format at each address:
 * - Length (4 bytes, big-endian) + Data
 * - For storage: Length = number of key-value pairs, then key1(32) + value1(32) + ...
 */
public class EvmStateProvider extends ComponentProviderAdapter {

    // Memory region base addresses
    private static final long CALLDATA_BASE = 0x40000000L;
    private static final long EVM_MEMORY_BASE = 0x50000000L;
    private static final long EVM_STACK_BASE = 0x60000000L;
    private static final long STORAGE_BASE = 0x70000000L;
    private static final long GAS_BASE = 0x80000000L;  // Gas info (gas at 0x80000000, gasCost at 0x80000004)

    private static final int STACK_ITEM_SIZE = 32;  // 256-bit stack items

    private final JPanel mainPanel;
    private final EvmStatePlugin plugin;

    // UI Components for each section
    private JTextArea calldataArea;
    private JTextArea memoryArea;
    private JTextArea stackArea;
    private JTextArea storageArea;
    private JLabel statusLabel;
    private JLabel snapshotLabel;
    private JLabel gasLabel;
    private JLabel gasCostLabel;

    // Current state
    private Trace currentTrace;
    private long currentSnap;

    public EvmStateProvider(PluginTool tool, EvmStatePlugin plugin) {
        super(tool, "EVM State Viewer", plugin.getName());
        this.plugin = plugin;

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Create the main content panel with 4 sections
        JPanel contentPanel = createContentPanel();
        mainPanel.add(contentPanel, BorderLayout.CENTER);

        // Create status panel at bottom
        JPanel statusPanel = createStatusPanel();
        mainPanel.add(statusPanel, BorderLayout.SOUTH);

        setHelpLocation(new ghidra.util.HelpLocation("EvmStateViewer", "Viewer"));
    }

    private JPanel createContentPanel() {
        // Use a 2x2 grid layout for the four panels
        JPanel panel = new JPanel(new GridLayout(2, 2, 5, 5));

        // Calldata panel (top-left)
        panel.add(createCalldataPanel());

        // Memory panel (top-right)
        panel.add(createMemoryPanel());

        // Stack panel (bottom-left)
        panel.add(createStackPanel());

        // Storage panel (bottom-right)
        panel.add(createStoragePanel());

        return panel;
    }

    private JPanel createCalldataPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Calldata"));

        calldataArea = new JTextArea();
        calldataArea.setEditable(false);
        calldataArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        calldataArea.setLineWrap(true);
        calldataArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(calldataArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createMemoryPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Memory"));

        memoryArea = new JTextArea();
        memoryArea.setEditable(false);
        memoryArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        memoryArea.setLineWrap(true);
        memoryArea.setWrapStyleWord(true);

        JScrollPane scrollPane = new JScrollPane(memoryArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createStackPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Stack"));

        stackArea = new JTextArea();
        stackArea.setEditable(false);
        stackArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        stackArea.setLineWrap(false);

        JScrollPane scrollPane = new JScrollPane(stackArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createStoragePanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Storage"));

        storageArea = new JTextArea();
        storageArea.setEditable(false);
        storageArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        storageArea.setLineWrap(false);

        JScrollPane scrollPane = new JScrollPane(storageArea);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createStatusPanel() {
        // Main bottom panel using GridBagLayout for better control
        JPanel bottomPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(0, 2, 0, 2);

        // Gas remaining panel (weight 0.15)
        JPanel gasPanel = new JPanel(new BorderLayout());
        gasPanel.setBorder(new TitledBorder("Gas Left"));
        gasLabel = new JLabel("--", SwingConstants.CENTER);
        gasLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
        gasLabel.setForeground(new Color(0, 100, 0));  // Dark green
        gasPanel.add(gasLabel, BorderLayout.CENTER);

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weightx = 0.15;
        gbc.weighty = 1.0;
        bottomPanel.add(gasPanel, gbc);

        // Gas cost panel (weight 0.15)
        JPanel gasCostPanel = new JPanel(new BorderLayout());
        gasCostPanel.setBorder(new TitledBorder("Gas Cost"));
        gasCostLabel = new JLabel("--", SwingConstants.CENTER);
        gasCostLabel.setFont(new Font(Font.MONOSPACED, Font.BOLD, 14));
        gasCostLabel.setForeground(new Color(180, 0, 0));  // Dark red
        gasCostPanel.add(gasCostLabel, BorderLayout.CENTER);

        gbc.gridx = 1;
        gbc.weightx = 0.15;
        bottomPanel.add(gasCostPanel, gbc);

        // Status panel (weight 0.70)
        JPanel statusPanel = new JPanel(new BorderLayout());
        statusPanel.setBorder(new TitledBorder("Status"));

        statusLabel = new JLabel("No trace loaded");
        statusPanel.add(statusLabel, BorderLayout.WEST);

        // Create right panel with snapshot label and refresh button
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));

        snapshotLabel = new JLabel("Snapshot: -");
        rightPanel.add(snapshotLabel);

        JButton refreshButton = new JButton("Refresh");
        refreshButton.addActionListener(e -> {
            statusLabel.setText("Refreshing...");
            plugin.refresh();
        });
        rightPanel.add(refreshButton);

        statusPanel.add(rightPanel, BorderLayout.EAST);

        gbc.gridx = 2;
        gbc.weightx = 0.70;
        bottomPanel.add(statusPanel, gbc);

        return bottomPanel;
    }

    /**
     * Update the state display with data from the trace at the given snapshot
     */
    public void updateState(Trace trace, long snap) {
        this.currentTrace = trace;
        this.currentSnap = snap;

        if (trace == null) {
            clearDisplay();
            return;
        }

        snapshotLabel.setText("Snapshot: " + snap);
        statusLabel.setText("Loading data...");

        try {
            // Read and display gas info
            updateGasInfo(trace, snap);

            // Read and display calldata
            String calldata = readCalldata(trace, snap);
            calldataArea.setText(calldata);

            // Read and display memory
            String memory = readMemory(trace, snap);
            memoryArea.setText(memory);

            // Read and display stack
            String stack = readStack(trace, snap);
            stackArea.setText(stack);

            // Read and display storage
            String storage = readStorage(trace, snap);
            storageArea.setText(storage);

            statusLabel.setText("Data loaded successfully");

        } catch (Exception e) {
            statusLabel.setText("Error: " + e.getMessage());
            MothraLog.error(this, "Error reading EVM state: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Clear the display
     */
    public void clearDisplay() {
        calldataArea.setText("No data available");
        memoryArea.setText("No data available");
        stackArea.setText("No data available");
        storageArea.setText("No data available");
        statusLabel.setText("No trace loaded");
        snapshotLabel.setText("Snapshot: -");
        gasLabel.setText("--");
        gasCostLabel.setText("--");
    }

    /**
     * Read and update gas information from trace memory at GAS_BASE
     * Format: gas (4 bytes, big-endian) at 0x80000000, gasCost (4 bytes, big-endian) at 0x80000004
     */
    private void updateGasInfo(Trace trace, long snap) {
        try {
            TraceMemoryManager memMgr = trace.getMemoryManager();
            AddressSpace ramSpace = trace.getBaseAddressFactory().getAddressSpace("ram");

            if (ramSpace == null) {
                gasLabel.setText("N/A");
                gasCostLabel.setText("N/A");
                return;
            }

            Address baseAddr = ramSpace.getAddress(GAS_BASE);

            // Read gas and gasCost (8 bytes total)
            byte[] buffer = new byte[8];
            int bytesRead = memMgr.getBytes(snap, baseAddr, ByteBuffer.wrap(buffer));

            if (bytesRead < 8) {
                gasLabel.setText("N/A");
                gasCostLabel.setText("N/A");
                return;
            }

            // Parse gas (4 bytes, big-endian, unsigned)
            long gas = ((buffer[0] & 0xFFL) << 24) |
                       ((buffer[1] & 0xFFL) << 16) |
                       ((buffer[2] & 0xFFL) << 8) |
                       (buffer[3] & 0xFFL);

            // Parse gasCost (4 bytes, big-endian, unsigned)
            long gasCost = ((buffer[4] & 0xFFL) << 24) |
                           ((buffer[5] & 0xFFL) << 16) |
                           ((buffer[6] & 0xFFL) << 8) |
                           (buffer[7] & 0xFFL);

            // Format with commas for readability
            gasLabel.setText(String.format("%,d", gas));
            gasCostLabel.setText(String.format("%,d", gasCost));

        } catch (Exception e) {
            gasLabel.setText("Error");
            gasCostLabel.setText("Error");
            MothraLog.error(this, "Error reading gas info: " + e.getMessage());
        }
    }

    /**
     * Read calldata from trace memory at CALLDATA_BASE
     * Format: length (4 bytes) + data
     */
    private String readCalldata(Trace trace, long snap) {
        try {
            TraceMemoryManager memMgr = trace.getMemoryManager();
            AddressSpace ramSpace = trace.getBaseAddressFactory().getAddressSpace("ram");

            if (ramSpace == null) {
                return "Error: RAM address space not found";
            }

            Address baseAddr = ramSpace.getAddress(CALLDATA_BASE);

            // Read length (4 bytes)
            byte[] lengthBytes = new byte[4];
            int bytesRead = memMgr.getBytes(snap, baseAddr, ByteBuffer.wrap(lengthBytes));

            if (bytesRead < 4) {
                return "No calldata (could not read length)";
            }

            int dataLength = ((lengthBytes[0] & 0xFF) << 24) |
                            ((lengthBytes[1] & 0xFF) << 16) |
                            ((lengthBytes[2] & 0xFF) << 8) |
                            (lengthBytes[3] & 0xFF);

            if (dataLength <= 0) {
                return "Calldata length: 0 bytes\n(empty)";
            }

            // Read data
            Address dataAddr = baseAddr.add(4);
            byte[] data = new byte[dataLength];
            bytesRead = memMgr.getBytes(snap, dataAddr, ByteBuffer.wrap(data));

            StringBuilder sb = new StringBuilder();
            sb.append("Length: ").append(dataLength).append(" bytes\n\n");
            sb.append("0x").append(bytesToHex(data));

            // If it looks like a function call, try to parse selector
            if (dataLength >= 4) {
                String selector = bytesToHex(data, 0, 4);
                sb.append("\n\nFunction selector: 0x").append(selector);
                if (dataLength > 4) {
                    sb.append("\nParameters: 0x").append(bytesToHex(data, 4, dataLength - 4));
                }
            }

            return sb.toString();

        } catch (Exception e) {
            return "Error reading calldata: " + e.getMessage();
        }
    }

    /**
     * Read EVM memory from trace memory at EVM_MEMORY_BASE
     * Format: length (4 bytes) + data
     */
    private String readMemory(Trace trace, long snap) {
        try {
            TraceMemoryManager memMgr = trace.getMemoryManager();
            AddressSpace ramSpace = trace.getBaseAddressFactory().getAddressSpace("ram");

            if (ramSpace == null) {
                return "Error: RAM address space not found";
            }

            Address baseAddr = ramSpace.getAddress(EVM_MEMORY_BASE);

            // Read length (4 bytes)
            byte[] lengthBytes = new byte[4];
            int bytesRead = memMgr.getBytes(snap, baseAddr, ByteBuffer.wrap(lengthBytes));

            if (bytesRead < 4) {
                return "No memory data (could not read length)";
            }

            int dataLength = ((lengthBytes[0] & 0xFF) << 24) |
                            ((lengthBytes[1] & 0xFF) << 16) |
                            ((lengthBytes[2] & 0xFF) << 8) |
                            (lengthBytes[3] & 0xFF);

            if (dataLength <= 0) {
                return "Memory size: 0 bytes\n(empty)";
            }

            // Read data
            Address dataAddr = baseAddr.add(4);
            byte[] data = new byte[Math.min(dataLength, 4096)]; // Limit to 4KB for display
            bytesRead = memMgr.getBytes(snap, dataAddr, ByteBuffer.wrap(data));

            StringBuilder sb = new StringBuilder();
            sb.append("Size: ").append(dataLength).append(" bytes");
            if (dataLength > 4096) {
                sb.append(" (showing first 4096)");
            }
            sb.append("\n\n");

            // Format as hex dump with offsets
            sb.append(formatHexDump(data, bytesRead));

            return sb.toString();

        } catch (Exception e) {
            return "Error reading memory: " + e.getMessage();
        }
    }

    /**
     * Read EVM stack from trace memory at EVM_STACK_BASE
     * Format: count (4 bytes) + items (32 bytes each)
     */
    private String readStack(Trace trace, long snap) {
        try {
            TraceMemoryManager memMgr = trace.getMemoryManager();
            AddressSpace ramSpace = trace.getBaseAddressFactory().getAddressSpace("ram");

            if (ramSpace == null) {
                return "Error: RAM address space not found";
            }

            Address baseAddr = ramSpace.getAddress(EVM_STACK_BASE);

            // Read count (4 bytes)
            byte[] countBytes = new byte[4];
            int bytesRead = memMgr.getBytes(snap, baseAddr, ByteBuffer.wrap(countBytes));

            if (bytesRead < 4) {
                return "No stack data (could not read count)";
            }

            int stackCount = ((countBytes[0] & 0xFF) << 24) |
                            ((countBytes[1] & 0xFF) << 16) |
                            ((countBytes[2] & 0xFF) << 8) |
                            (countBytes[3] & 0xFF);

            if (stackCount <= 0) {
                return "Stack depth: 0\n(empty)";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Stack depth: ").append(stackCount).append("\n\n");

            // Read each stack item (32 bytes each)
            Address dataAddr = baseAddr.add(4);
            for (int i = 0; i < stackCount && i < 256; i++) { // Limit to 256 items
                byte[] item = new byte[STACK_ITEM_SIZE];
                Address itemAddr = dataAddr.add(i * STACK_ITEM_SIZE);
                memMgr.getBytes(snap, itemAddr, ByteBuffer.wrap(item));

                BigInteger value = new BigInteger(1, item);
                String hexValue = value.toString(16);

                // Format: [index] 0xvalue
                sb.append(String.format("[%3d] 0x%s%n", i, hexValue));
            }

            if (stackCount > 256) {
                sb.append("... (").append(stackCount - 256).append(" more items)");
            }

            return sb.toString();

        } catch (Exception e) {
            return "Error reading stack: " + e.getMessage();
        }
    }

    /**
     * Read storage from trace memory at STORAGE_BASE
     * Format: count (4 bytes) + key-value pairs (32 + 32 bytes each)
     */
    private String readStorage(Trace trace, long snap) {
        try {
            TraceMemoryManager memMgr = trace.getMemoryManager();
            AddressSpace ramSpace = trace.getBaseAddressFactory().getAddressSpace("ram");

            if (ramSpace == null) {
                return "Error: RAM address space not found";
            }

            Address baseAddr = ramSpace.getAddress(STORAGE_BASE);

            // Read count (4 bytes)
            byte[] countBytes = new byte[4];
            int bytesRead = memMgr.getBytes(snap, baseAddr, ByteBuffer.wrap(countBytes));

            if (bytesRead < 4) {
                return "No storage data (could not read count)";
            }

            int pairCount = ((countBytes[0] & 0xFF) << 24) |
                           ((countBytes[1] & 0xFF) << 16) |
                           ((countBytes[2] & 0xFF) << 8) |
                           (countBytes[3] & 0xFF);

            if (pairCount <= 0) {
                return "Storage slots: 0\n(empty)";
            }

            StringBuilder sb = new StringBuilder();
            sb.append("Storage slots: ").append(pairCount).append("\n\n");

            // Read each key-value pair (64 bytes each: 32 key + 32 value)
            Address dataAddr = baseAddr.add(4);
            for (int i = 0; i < pairCount && i < 256; i++) { // Limit to 256 pairs
                byte[] keyBytes = new byte[STACK_ITEM_SIZE];
                byte[] valueBytes = new byte[STACK_ITEM_SIZE];

                Address keyAddr = dataAddr.add(i * 64);
                Address valueAddr = keyAddr.add(STACK_ITEM_SIZE);

                memMgr.getBytes(snap, keyAddr, ByteBuffer.wrap(keyBytes));
                memMgr.getBytes(snap, valueAddr, ByteBuffer.wrap(valueBytes));

                BigInteger key = new BigInteger(1, keyBytes);
                BigInteger value = new BigInteger(1, valueBytes);

                // Format: slot[key] = value
                sb.append(String.format("slot[0x%s] = 0x%s%n",
                    key.toString(16), value.toString(16)));
            }

            if (pairCount > 256) {
                sb.append("... (").append(pairCount - 256).append(" more slots)");
            }

            return sb.toString();

        } catch (Exception e) {
            return "Error reading storage: " + e.getMessage();
        }
    }

    /**
     * Convert bytes to hex string
     */
    private String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length);
    }

    private String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < bytes.length; i++) {
            sb.append(String.format("%02x", bytes[i] & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Format bytes as hex dump with offsets
     */
    private String formatHexDump(byte[] data, int length) {
        StringBuilder sb = new StringBuilder();
        int bytesPerLine = 32;

        for (int offset = 0; offset < length; offset += bytesPerLine) {
            // Offset
            sb.append(String.format("%04x: ", offset));

            // Hex bytes
            for (int i = 0; i < bytesPerLine && offset + i < length; i++) {
                sb.append(String.format("%02x", data[offset + i] & 0xFF));
                if (i % 4 == 3) {
                    sb.append(" ");
                }
            }

            sb.append("\n");
        }

        return sb.toString();
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
