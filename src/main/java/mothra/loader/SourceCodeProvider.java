package mothra.loader;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import javax.swing.JComponent;
import javax.swing.JPanel;

import javax.swing.border.EmptyBorder;

import org.fife.ui.rsyntaxtextarea.RSyntaxTextArea;
import org.fife.ui.rsyntaxtextarea.SyntaxConstants;
import org.fife.ui.rtextarea.RTextScrollPane;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import db.DBHandle;
import db.DBRecord;
import db.Table;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

public class SourceCodeProvider extends ComponentProviderAdapter {

    // Etherscan API configuration
    private static final String ETHERSCAN_API_URL = "https://api.etherscan.io/v2/api";
    private static final String ETHERSCAN_API_KEY = "EWFME7AH6URPNUIKUDJR4ZQ9H7S8IK3ZHG";
    private static final String CHAIN_ID = "1"; // Ethereum mainnet
    private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();

    private final RSyntaxTextArea textArea = new RSyntaxTextArea(20, 60);
    private final JPanel mainPanel;
    private final ProgramPlugin plugin;
    private Address currentAddress;
    private ProgramSelection currentSelection;

    SourceCodeProvider(PluginTool tool, ProgramPlugin plugin) {
        super(tool, "EVM Contract Source", plugin.getName());
        this.plugin = plugin;

        // Create the main panel
        mainPanel = new JPanel(new BorderLayout());
        mainPanel.setBorder(new EmptyBorder(5, 5, 5, 5));

        // Create top panel with controls
        JPanel topPanel = createTopPanel();
        mainPanel.add(topPanel, BorderLayout.NORTH);

        // Configure the text area with syntax highlighting
        textArea.setEditable(false);
        textArea.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT); // Use JavaScript syntax for Solidity
        textArea.setCodeFoldingEnabled(true);
        textArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        // Create scroll pane for main text area
        RTextScrollPane scrollPane = new RTextScrollPane(textArea);
        scrollPane.setPreferredSize(new Dimension(600, 400));

        // Add to main panel
        mainPanel.add(scrollPane, BorderLayout.CENTER);

        // Create bottom panel with status
        JPanel bottomPanel = createBottomPanel();
        mainPanel.add(bottomPanel, BorderLayout.SOUTH);

        // Set up the component
        setHelpLocation(new ghidra.util.HelpLocation("EvmSourceViewer", "Viewer"));

        // Initial content
        initializeDisplay();
    }

    /**
     * Get the current program from the plugin.
     */
    private Program getCurrentProgram() {
        return plugin.getCurrentProgram();
    }

    private String fetchContractSourceCode(String contractAddress) {
        try {
            String apiUrl = String.format("%s?chainid=%s&module=contract&action=getsourcecode&address=%s&apikey=%s",
                    ETHERSCAN_API_URL, CHAIN_ID, contractAddress, ETHERSCAN_API_KEY);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(apiUrl))
                    .timeout(Duration.ofSeconds(30))
                    .GET()
                    .build();

            HttpResponse<String> response = HTTP_CLIENT.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                return "// Error: Failed to fetch source code (HTTP " + response.statusCode() + ")";
            }

            JsonNode rootNode = JSON_MAPPER.readTree(response.body());
            String status = rootNode.path("status").asText();

            if (!"1".equals(status)) {
                return "// Error: Contract not verified on Etherscan";
            }

            JsonNode resultNode = rootNode.path("result");
            if (!resultNode.isArray() || resultNode.size() == 0) {
                return "// Error: No contract data found";
            }

            JsonNode contractNode = resultNode.get(0);
            String sourceCode = contractNode.path("SourceCode").asText();

            if (sourceCode.isEmpty()) {
                return "// No source code available";
            }

            // Check if the source code is a JSON structure (starts with {)
            if (sourceCode.trim().startsWith("{") || sourceCode.trim().startsWith("{{")) {

                try {
                    // Clean up the source code - remove any leading {{ or trailing }}
                    String cleanedSourceCode = sourceCode.trim();

                    if (cleanedSourceCode.startsWith("{{")) {
                        cleanedSourceCode = cleanedSourceCode.substring(2);

                        // Check if the content already has proper JSON braces
                        if (!cleanedSourceCode.startsWith("{")) {
                            cleanedSourceCode = "{" + cleanedSourceCode;

                        }
                    }
                    if (cleanedSourceCode.endsWith("}}")) {
                        cleanedSourceCode = cleanedSourceCode.substring(0, cleanedSourceCode.length() - 2);

                        // Check if the content already has proper JSON braces
                        if (!cleanedSourceCode.endsWith("}")) {
                            cleanedSourceCode = cleanedSourceCode + "}";

                        }
                    }

                    String parsedResult = parseStructuredSourceCode(cleanedSourceCode);
                    return parsedResult;
                } catch (Exception e) {
                    // If parsing fails, return the raw source code
                    return "// Error parsing structured source code: " + e.getMessage() + "\n\n" + sourceCode;
                }
            }

            return sourceCode;

        } catch (Exception e) {
            return "// Error fetching source code: " + e.getMessage();
        }
    }

    /**
     * Parse structured source code that contains multiple files
     */
    private String parseStructuredSourceCode(String jsonSourceCode) throws Exception {
        JsonNode sourceNode = JSON_MAPPER.readTree(jsonSourceCode);

        StringBuilder result = new StringBuilder();
        result.append("// Contract Source Code (Multiple Files)\n");
        result.append("// ======================================\n\n");

        // Get the sources object
        JsonNode sourcesNode = sourceNode.path("sources");
        if (sourcesNode.isMissingNode()) {
            return "// No source files found";
        }

        // Get all field names and sort them for consistent display
        java.util.List<String> fileNames = new java.util.ArrayList<>();
        var fieldNames = sourcesNode.fieldNames();
        while (fieldNames.hasNext()) {
            fileNames.add(fieldNames.next());
        }
        java.util.Collections.sort(fileNames);

        // Process each source file
        for (String fileName : fileNames) {
            JsonNode fileNode = sourcesNode.get(fileName);
            if (fileNode != null && fileNode.has("content")) {
                String content = fileNode.get("content").asText();
                if (content != null && !content.isEmpty()) {
                    result.append("// File: ").append(fileName).append("\n");
                    result.append("// ").append("=".repeat(50)).append("\n");
                    result.append(content).append("\n\n");
                }
            }
        }

        return result.toString();
    }

    private JPanel createTopPanel() {
        // No buttons needed, just return empty panel
        return new JPanel();
    }

    private JPanel createBottomPanel() {
        return new JPanel(); // No status panel needed
    }

    /**
     * Initialize the display with default content.
     */
    public void initializeDisplay() {
        setText("// EVM Contract Source Viewer\n// Select an address or range to view source code");
    }

    /**
     * Find the first contract address from the ContractInfo table.
     */
    private String findFirstContractAddress(Program program) {
        if (!(program instanceof ProgramDB)) {
            return null;
        }

        try {
            ProgramDB programDB = (ProgramDB) program;
            DBHandle dbHandle = programDB.getDBHandle();
            Table contractInfoTable = dbHandle.getTable("ContractInfo");

            if (contractInfoTable == null || contractInfoTable.getRecordCount() == 0) {
                return null;
            }

            // Get the first record
            var records = contractInfoTable.iterator();
            if (records.hasNext()) {
                DBRecord record = records.next();
                String contractAddr = record.getString(0);
                return contractAddr;
            }

        } catch (Exception e) {
            // Silent fail
        }

        return null;
    }

    /**
     * Handle location changes from the Listing window.
     * This is called when the user moves the cursor or selects text in the Listing.
     */
    public void programLocationChanged(ProgramLocation location) {
        if (location != null && location.getAddress() != null) {
            currentAddress = location.getAddress();
            updateContentForAddress(currentAddress);
        }
    }

    /**
     * Handle selection changes from the Listing window.
     * This is called when the user selects a range of addresses.
     */
    public void selectionChanged(ProgramSelection selection) {
        currentSelection = selection;
        updateContentForSelection(selection);
    }

    /**
     * Find the contract address for a given memory address by querying the
     * ContractInfo table.
     */
    private String findContractAddressForAddress(Address address) {
        if (getCurrentProgram() == null || !(getCurrentProgram() instanceof ProgramDB)) {
            return null;
        }

        try {
            ProgramDB programDB = (ProgramDB) getCurrentProgram();
            DBHandle dbHandle = programDB.getDBHandle();
            Table contractInfoTable = dbHandle.getTable("ContractInfo");

            if (contractInfoTable == null) {
                return null;
            }

            long addressOffset = address.getOffset();
            long contractSpacing = 0x10000L;

            var records = contractInfoTable.iterator();
            while (records.hasNext()) {
                DBRecord record = records.next();
                String contractAddr = record.getString(0);
                long baseOffset = record.getLongValue(1);

                if (addressOffset >= baseOffset && addressOffset < baseOffset + contractSpacing) {
                    return contractAddr;
                }
            }

        } catch (Exception e) {
            // Silent error handling
        }

        return null;
    }

    /**
     * Update the content area with information about the selected address.
     */
    private void updateContentForAddress(Address address) {
        String contractAddress = findContractAddressForAddress(address);
        if (contractAddress != null) {
            String sourceCode = fetchContractSourceCode(contractAddress);
            setText(sourceCode);
        }
    }

    /**
     * Update the content area with information about the selected range.
     */
    private void updateContentForSelection(ProgramSelection selection) {
        if (selection != null) {
            Address firstAddress = selection.getMinAddress();
            String contractAddress = findContractAddressForAddress(firstAddress);
            if (contractAddress != null) {
                String sourceCode = fetchContractSourceCode(contractAddress);
                setText(sourceCode);
            }
        }
    }

    /**
     * Set text in the text pane
     */
    private void setText(String text) {
        if (text == null || text.isEmpty()) {
            textArea.setText("");
            return;
        }
        textArea.setText(text);
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }
}