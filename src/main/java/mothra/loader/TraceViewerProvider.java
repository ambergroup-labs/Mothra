package mothra.loader;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTree;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import db.DBHandle;
import db.Table;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class TraceViewerProvider extends ComponentProviderAdapter {

    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private final JTextArea textArea = new JTextArea();
    private final JTree traceTree = new JTree();
    private final JPanel mainPanel;
    private JLabel statusLabel;
    private JLabel addressLabel;
    private final ProgramPlugin plugin;
    private Address currentAddress;
    private ProgramSelection currentSelection;

    public TraceViewerProvider(PluginTool tool, ProgramPlugin plugin) {
        super(tool, "EVM Trace Viewer", plugin.getName());
        this.plugin = plugin;

        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        JPanel centerPanel = createCenterPanel();
        mainPanel.add(centerPanel, BorderLayout.CENTER);

        JPanel bottomPanel = createBottomPanel();
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        setHelpLocation(new ghidra.util.HelpLocation("TraceViewer", "Viewer"));

        loadTransactionTrace();
    }

    private Program getCurrentProgram() {
        return plugin.getCurrentProgram();
    }

    private JPanel createCenterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Transaction Trace"));

        traceTree.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        traceTree.setRootVisible(false);
        traceTree.setShowsRootHandles(true);

        traceTree.addTreeSelectionListener(new javax.swing.event.TreeSelectionListener() {
            @Override
            public void valueChanged(javax.swing.event.TreeSelectionEvent e) {
                DefaultMutableTreeNode node = (DefaultMutableTreeNode) traceTree.getLastSelectedPathComponent();
                if (node != null) {
                    if (node instanceof CallTreeNode) {
                        CallTreeNode callNode = (CallTreeNode) node;
                        displayTraceDetails(callNode.getDisplayText(), callNode.getCallData());
                    } else if (node.getUserObject() instanceof String) {
                        String nodeText = (String) node.getUserObject();
                        displayTraceDetails(nodeText, null);
                    }
                }
            }
        });

        JScrollPane treeScrollPane = new JScrollPane(traceTree);
        treeScrollPane.setPreferredSize(new Dimension(300, 200));
        treeScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        treeScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        textArea.setEditable(false);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        textArea.setLineWrap(false);
        textArea.setWrapStyleWord(false);

        JScrollPane textScrollPane = new JScrollPane(textArea);
        textScrollPane.setPreferredSize(new Dimension(300, 150));
        textScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        textScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);

        panel.add(treeScrollPane, BorderLayout.CENTER);
        panel.add(textScrollPane, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createBottomPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(new TitledBorder("Status"));

        statusLabel = new JLabel("Ready");
        panel.add(statusLabel, BorderLayout.WEST);

        addressLabel = new JLabel("No address selected");
        addressLabel.setBorder(new EmptyBorder(2, 10, 2, 5));
        panel.add(addressLabel, BorderLayout.EAST);

        return panel;
    }

    public void loadTransactionTrace() {
        Program currentProgram = getCurrentProgram();
        if (currentProgram == null) {
            statusLabel.setText("No program loaded");
            return;
        }

        if (loadTraceFromDatabase()) {
            return;
        }

        statusLabel.setText("No trace data found");
        clearTraceDisplay();
    }

    private boolean loadTraceFromDatabase() {
        if (!(getCurrentProgram() instanceof ProgramDB)) {
            return false;
        }

        try {
            ProgramDB programDB = (ProgramDB) getCurrentProgram();
            DBHandle dbHandle = programDB.getDBHandle();

            Table callTracerTable = dbHandle.getTable("CallTracer");
            if (callTracerTable != null) {
                Map<String, Object> callTracerData = loadCallTracerFromDatabase(callTracerTable);
                if (callTracerData != null) {
                    displayCallTracerData(callTracerData);
                    statusLabel.setText("Loaded call tracer data from database");
                    return true;
                }
            }

            if (loadTraceFromFiles()) {
                return true;
            }
        } catch (Exception e) {
            System.err.println("Error loading trace from database: " + e.getMessage());
            e.printStackTrace();
        }

        return false;
    }

    private boolean loadTraceFromFiles() {
        try {
            java.io.File jsonFile = new java.io.File("ghidra_scripts/callTracer.json");
            if (jsonFile.exists()) {
                Map<String, Object> callTracerData = loadCallTracerData();
                if (callTracerData != null) {
                    displayCallTracerData(callTracerData);
                    statusLabel.setText("Loaded callTracer data from file");
                    return true;
                }
            }

            java.io.File traceFile = new java.io.File("ghidra_scripts/trace.json");
            if (traceFile.exists()) {
                Map<String, Object> traceData = loadTraceData(traceFile);
                if (traceData != null) {
                    displayCallTracerData(traceData);
                    statusLabel.setText("Loaded trace data from file");
                    return true;
                }
            }

            java.io.File txTraceFile = new java.io.File("ghidra_scripts/traceTransaction.json");
            if (txTraceFile.exists()) {
                Map<String, Object> txTraceData = loadTransactionTraceData(txTraceFile);
                if (txTraceData != null) {
                    displayCallTracerData(txTraceData);
                    statusLabel.setText("Loaded transaction trace data from file");
                    return true;
                }
            }

        } catch (Exception e) {
            System.err.println("Error loading trace from files: " + e.getMessage());
            e.printStackTrace();
        }

        return false;
    }

    private Map<String, Object> loadTraceData(java.io.File traceFile) {
        try {
            String jsonContent = new String(java.nio.file.Files.readAllBytes(traceFile.toPath()));
            JsonNode rootNode = JSON_MAPPER.readTree(jsonContent);

            if (rootNode.has("result")) {
                return JSON_MAPPER.convertValue(rootNode.get("result"), Map.class);
            } else if (rootNode.has("traces")) {
                return JSON_MAPPER.convertValue(rootNode.get("traces"), Map.class);
            } else if (rootNode.has("trace")) {
                return JSON_MAPPER.convertValue(rootNode.get("trace"), Map.class);
            }

            return JSON_MAPPER.convertValue(rootNode, Map.class);

        } catch (Exception e) {
            System.err.println("Error reading trace.json: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> loadTransactionTraceData(java.io.File txTraceFile) {
        try {
            String jsonContent = new String(java.nio.file.Files.readAllBytes(txTraceFile.toPath()));
            JsonNode rootNode = JSON_MAPPER.readTree(jsonContent);

            if (rootNode.has("result")) {
                return JSON_MAPPER.convertValue(rootNode.get("result"), Map.class);
            } else if (rootNode.has("transaction")) {
                return JSON_MAPPER.convertValue(rootNode.get("transaction"), Map.class);
            }

            return JSON_MAPPER.convertValue(rootNode, Map.class);

        } catch (Exception e) {
            System.err.println("Error reading traceTransaction.json: " + e.getMessage());
            return null;
        }
    }

    private Map<String, Object> loadCallTracerFromDatabase(Table callTracerTable) {
        try {

            // Read call tracer data from the CallTracer table
            // Schema: ["from", "to", "type", "gas", "gasUsed", "value", "calls"]

            if (callTracerTable.getRecordCount() == 0) {
                return null;
            }

            // Get the first record (root call trace)
            db.DBRecord record = callTracerTable.getRecord(0);
            if (record == null) {
                return null;
            }

            Map<String, Object> callTracerData = new HashMap<>();

            String from = record.getString(0);
            String to = record.getString(1);
            String type = record.getString(2);
            String gas = record.getString(3);
            String gasUsed = record.getString(4);
            String value = record.getString(5);

            callTracerData.put("from", from);
            callTracerData.put("to", to);
            callTracerData.put("type", type);
            callTracerData.put("gas", gas);
            callTracerData.put("gasUsed", gasUsed);
            callTracerData.put("value", value);

            // Parse the nested calls from JSON
            try {
                String callsJson = record.getString(6);

                if (callsJson != null && !callsJson.isEmpty()) {
                    @SuppressWarnings("unchecked")
                    List<Map<String, Object>> calls = JSON_MAPPER.readValue(callsJson, List.class);
                    callTracerData.put("calls", calls);
                } else {
                    callTracerData.put("calls", new ArrayList<>());
                }
            } catch (Exception e) {
                callTracerData.put("calls", new ArrayList<>());
            }

            return callTracerData;

        } catch (Exception e) {
            System.err.println("Error loading call tracer from database: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Object> loadStructLogsFromDatabase(Table structLogsTable) {
        try {

            List<Map<String, Object>> structLogs = new ArrayList<>();

            for (int i = 0; i < structLogsTable.getRecordCount(); i++) {
                try {
                    db.DBRecord record = structLogsTable.getRecord(i);
                    if (record != null) {
                        Map<String, Object> logEntry = new HashMap<>();

                        logEntry.put("pc", record.getIntValue(0)); // Program counter
                        logEntry.put("op", record.getString(1)); // Opcode
                        logEntry.put("gas", record.getIntValue(2)); // Gas
                        logEntry.put("gasCost", record.getIntValue(3)); // Gas cost
                        logEntry.put("depth", record.getIntValue(4)); // Call depth

                        try {
                            String stackJson = record.getString(5);
                            if (stackJson != null && !stackJson.isEmpty()) {
                                @SuppressWarnings("unchecked")
                                List<String> stack = JSON_MAPPER.readValue(stackJson, List.class);
                                logEntry.put("stack", stack);
                            } else {
                                logEntry.put("stack", new ArrayList<>());
                            }
                        } catch (Exception e) {
                            logEntry.put("stack", new ArrayList<>());
                        }

                        structLogs.add(logEntry);
                    }
                } catch (Exception e) {
                    System.err.println("Error reading record " + i + ": " + e.getMessage());
                }
            }

            if (structLogs.isEmpty()) {
                return null;
            }

            Map<String, Object> result = new HashMap<>();
            result.put("structLogs", structLogs);
            result.put("type", "structLogs");
            result.put("source", "StructLogs table");

            return result;

        } catch (Exception e) {
            System.err.println("Error loading from database table: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private Map<String, Object> loadCallTracerData() {
        try {
            java.io.File jsonFile = new java.io.File("ghidra_scripts/callTracer.json");
            if (!jsonFile.exists()) {
                System.err.println("callTracer.json not found at: " + jsonFile.getAbsolutePath());
                return null;
            }

            String jsonContent = new String(java.nio.file.Files.readAllBytes(jsonFile.toPath()));
            JsonNode rootNode = JSON_MAPPER.readTree(jsonContent);

            JsonNode resultNode = rootNode.get("result");
            if (resultNode == null) {
                System.err.println("No 'result' field found in callTracer.json");
                return null;
            }

            return JSON_MAPPER.convertValue(resultNode, Map.class);

        } catch (Exception e) {
            System.err.println("Error reading callTracer.json: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private void displayCallTracerData(Map<String, Object> callTracerData) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("Transaction Trace");

        String from = (String) callTracerData.get("from");
        String to = (String) callTracerData.get("to");
        String gasUsed = (String) callTracerData.get("gasUsed");
        String value = (String) callTracerData.get("value");
        String type = (String) callTracerData.get("type");

        String rootText = String.format("Root: %s → %s (Gas: %s, Value: %s, Type: %s)",
                formatAddress(from), formatAddress(to), gasUsed, value != null ? value : "0x0",
                type != null ? type : "CALL");
        DefaultMutableTreeNode rootNode = new DefaultMutableTreeNode(rootText);
        root.add(rootNode);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> calls = (List<Map<String, Object>>) callTracerData.get("calls");
        if (calls != null) {
            processCallsRecursively(calls, rootNode);
        }

        traceTree.setModel(new DefaultTreeModel(root));

        for (int i = 0; i < traceTree.getRowCount(); i++) {
            traceTree.expandRow(i);
        }
    }

    private void processCallsRecursively(List<Map<String, Object>> calls, DefaultMutableTreeNode parentNode) {
        for (Map<String, Object> call : calls) {
            String type = (String) call.get("type");
            String from = (String) call.get("from");
            String to = (String) call.get("to");
            String gasUsed = (String) call.get("gasUsed");
            String gas = (String) call.get("gas");
            String value = (String) call.get("value");

            String nodeText = String.format("%s: %s → %s (Gas: %s, Used: %s, Value: %s)",
                    type, formatAddress(from), formatAddress(to), gas, gasUsed, value != null ? value : "0x0");

            DefaultMutableTreeNode callNode = new CallTreeNode(nodeText, call);
            parentNode.add(callNode);

            @SuppressWarnings("unchecked")
            List<Map<String, Object>> nestedCalls = (List<Map<String, Object>>) call.get("calls");
            if (nestedCalls != null && !nestedCalls.isEmpty()) {
                processCallsRecursively(nestedCalls, callNode);
            }
        }
    }

    private void clearTraceDisplay() {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode("No Trace Data Available");
        traceTree.setModel(new DefaultTreeModel(root));

        textArea.setText(
                "No transaction trace data found.\n\nTo view trace data:\n1. Load a program with trace data\n2. Ensure callTracer.json is available\n3. Check database for CallTracer table (preferred) or StructLogs table\n4. All data sources now use the same display format for consistency");
    }

    public void showProvider() {
        setVisible(true);
        toFront();
    }

    private void displayTraceDetails(String nodeText, Map<String, Object> callData) {
        if (nodeText.startsWith("Root:")) {
            statusLabel.setText("Root transaction selected");
            addressLabel.setText("Transaction overview");
            textArea.setText("Root transaction details will be displayed here.");
            return;
        }

        if (callData != null) {
            String type = (String) callData.get("type");
            String from = (String) callData.get("from");
            String to = (String) callData.get("to");
            String gas = (String) callData.get("gas");
            String gasUsed = (String) callData.get("gasUsed");
            String value = (String) callData.get("value");
            String input = (String) callData.get("input");
            String output = (String) callData.get("output");

            statusLabel.setText("Selected: " + type + " call");
            addressLabel.setText("From: " + formatAddress(from) + " → To: " + formatAddress(to));

            StringBuilder details = new StringBuilder();
            details.append("Call Type: ").append(type).append("\n");
            details.append("From: ").append(from).append("\n");
            details.append("To: ").append(to).append("\n");
            details.append("Gas Allocated: ").append(gas).append("\n");
            details.append("Gas Used: ").append(gasUsed).append("\n");
            details.append("Value: ").append(value != null ? value : "0x0").append("\n");

            if (input != null && !input.isEmpty()) {
                details.append("Input: ").append(input).append("\n");
            }

            if (output != null && !output.isEmpty()) {
                details.append("Output: ").append(output).append("\n");
            }

            textArea.setText(details.toString());

        } else {
            try {
                String[] parts = nodeText.split(" → ");
                if (parts.length >= 2) {
                    String callType = parts[0].split(": ")[0];
                    String from = parts[0].split(": ")[1];
                    String to = parts[1].split(" \\(")[0];

                    statusLabel.setText("Selected: " + callType + " call");
                    addressLabel.setText("From: " + from + " → To: " + to);
                    textArea.setText("Limited information available for this trace node.");
                }
            } catch (Exception e) {
                statusLabel.setText("Error parsing trace details");
                addressLabel.setText("Invalid selection");
                textArea.setText("Error: Could not parse trace details.");
            }
        }
    }

    public void programLocationChanged(ProgramLocation location) {
        if (location == null || getCurrentProgram() == null) {
            addressLabel.setText("No address selected");
            return;
        }

        Address address = location.getAddress();
        if (address == null) {
            addressLabel.setText("No address selected");
            return;
        }

        currentAddress = address;
        String addressStr = address.toString();
        addressLabel.setText("Address: " + addressStr);

        highlightTraceForAddress(address);
    }

    public void selectionChanged(ProgramSelection selection) {
        currentSelection = selection;

        if (selection == null || selection.isEmpty()) {
            addressLabel.setText("No selection");
            return;
        }

        Address minAddr = selection.getMinAddress();
        Address maxAddr = selection.getMaxAddress();

        String selectionStr = "Range: " + minAddr.toString() + " - " + maxAddr.toString();
        addressLabel.setText(selectionStr);

        highlightTraceForSelection(selection);
    }

    private void highlightTraceForAddress(Address address) {
        statusLabel.setText("Address selected: " + address.toString());
    }

    private void highlightTraceForSelection(ProgramSelection selection) {
        statusLabel.setText("Selection: " + selection.getNumAddressRanges() + " ranges");
    }

    private String formatAddress(String address) {
        if (address == null || address.length() < 8) {
            return address;
        }
        return address.substring(0, 6) + "..." + address.substring(address.length() - 4);
    }

    private static class CallTreeNode extends DefaultMutableTreeNode {
        private final Map<String, Object> callData;
        private final String displayText;

        public CallTreeNode(String displayText, Map<String, Object> callData) {
            super(displayText);
            this.displayText = displayText;
            this.callData = callData;
        }

        public Map<String, Object> getCallData() {
            return callData;
        }

        public String getDisplayText() {
            return displayText;
        }
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}
