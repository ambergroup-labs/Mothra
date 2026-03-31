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
package mothra;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.DefaultBlockParameterName;
import org.web3j.protocol.core.methods.response.EthGetCode;
import org.web3j.protocol.http.HttpService;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.util.Msg;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loader.ImporterSettings;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.main.AppInfo;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.main.FrontEndService;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.util.HelpLocation;
import ghidra.util.task.Task;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import mothra.loader.EVMLoader;
import mothra.loader.TraceLoader;
import mothra.trace.data.DataStore;
import mothra.trace.data.TraceConfiguration;
import mothra.trace.rpc.EthereumRpcClient;
import mothra.trace.util.CacheManager;
import mothra.trace.generator.TraceGeneratorCore;
import mothra.util.MothraLog;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.DomainFile;
import java.io.File;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Import External Files Through Address or Bytecode",
    description = "This plugin allows the import of external files into the project, providing extended functionality for handling different types of data.",
    eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class MothraPlugin extends Plugin
		implements ApplicationLevelPlugin, ProjectListener {

	private static final String SIMPLE_UNPACK_OPTION = "";
	private static final boolean SIMPLE_UNPACK_OPTION_DEFAULT = false;
	private static final String RPC_URL_OPTION = "Mothra.RPC_URL";
	private static final String RPC_URL_DEFAULT = "http://localhost:8545";

	private DockingAction downloadBytecodeAction;
	private GhidraFileChooser chooser;
	private FrontEndService frontEndService;

	public MothraPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();

		frontEndService = tool.getService(FrontEndService.class);
		if (frontEndService != null) {
			frontEndService.addProjectListener(this);

			ToolOptions options = tool.getOptions(ToolConstants.FILE_IMPORT_OPTIONS);
			HelpLocation help = new HelpLocation("ImporterPlugin", "Project_Tree");

			options.registerOption(SIMPLE_UNPACK_OPTION, SIMPLE_UNPACK_OPTION_DEFAULT, help,
					"Perform simple unpack when any packed DB file is imported");
		}

		// Register RPC URL option for persistence
		ToolOptions mothraOptions = tool.getOptions("Mothra");
		HelpLocation mothraHelp = new HelpLocation("Mothra", "RPC_Configuration");
		mothraOptions.registerOption(RPC_URL_OPTION, RPC_URL_DEFAULT, mothraHelp,
				"Default RPC endpoint URL for Ethereum node connection");

		setupDownloadBytecodeAction();
	}

	@Override
	protected void dispose() {
		super.dispose();
		if (downloadBytecodeAction != null) {
			downloadBytecodeAction.dispose();
		}
		if (frontEndService != null) {
			frontEndService.removeProjectListener(this);
			frontEndService = null;
		}

		if (chooser != null) {
			chooser.dispose();
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);

		if (event instanceof ProgramActivatedPluginEvent) {
			ProgramActivatedPluginEvent pape = (ProgramActivatedPluginEvent) event;
			// Update the transaction trace provider when a new program is activated
			// This functionality is now handled by the TransactionTracePlugin
		}
	}

	private void setupDownloadBytecodeAction() {
		downloadBytecodeAction = new DockingAction("Download ByteCode", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				showDownloadBytecodeDialog();
			}
		};
		downloadBytecodeAction
				.setMenuBarData(new MenuData(new String[] { "&File", "Download ByteCode" }, null,
						"Import", MenuData.NO_MNEMONIC, "1"));
		downloadBytecodeAction.setKeyBindingData(null);
		downloadBytecodeAction.setEnabled(true);
		downloadBytecodeAction.markHelpUnnecessary();
		tool.addAction(downloadBytecodeAction);
	}

	@Override
	public void projectClosed(Project project) {
		// No-ops
	}

	@Override
	public void projectOpened(Project project) {
		// No-ops
	}

	/**
	 * Get the saved RPC URL from tool options
	 */
	private String getSavedRpcUrl() {
		ToolOptions options = tool.getOptions("Mothra");
		return options.getString(RPC_URL_OPTION, RPC_URL_DEFAULT);
	}

	/**
	 * Save the RPC URL to tool options
	 */
	private void saveRpcUrl(String rpcUrl) {
		if (rpcUrl != null && !rpcUrl.trim().isEmpty()) {
			ToolOptions options = tool.getOptions("Mothra");
			options.setString(RPC_URL_OPTION, rpcUrl.trim());
		}
	}

	private void showDownloadBytecodeDialog() {
		JDialog dialog = createDialog("Download ByteCode");

		// Create the necessary input components
		// Use JTextField for single-line inputs (RPC URL and filename)
		JTextField rpcUrlField = new JTextField(50);
		rpcUrlField.setText(getSavedRpcUrl());  // Load saved RPC URL
		JTextField filenameField = new JTextField(50);
		// Use JTextArea for multi-line input (bytecode can be very long)
		JTextArea fetchBytecodeOptionTextArea = createTextArea(10, 50);

		// Set up the main content
		setupMainContent(dialog, rpcUrlField, filenameField,
				fetchBytecodeOptionTextArea);

		// Set up the buttons and their actions
		setupButtonsAndActions(dialog, rpcUrlField, filenameField,
				fetchBytecodeOptionTextArea);

		// Finalize the dialog setup
		finalizeDialog(dialog);
	}

	private JDialog createDialog(String title) {
		JDialog dialog = new JDialog(tool.getToolFrame(), title, true);
		dialog.setLayout(new BorderLayout());
		return dialog;
	}

	private JTextArea createTextArea(int rows, int columns) {
		JTextArea textArea = new JTextArea(rows, columns);
		textArea.setWrapStyleWord(true);
		textArea.setLineWrap(true);
		return textArea;
	}

	private void setupMainContent(JDialog dialog, JTextField rpcUrlField,
			JTextField filenameField,
			JTextArea fetchBytecodeOptionTextArea) {
		// Create top panel for single-line inputs (minimal height)
		JPanel topPanel = new JPanel(new GridLayout(2, 1, 5, 5));
		topPanel.add(createPanel("RPC Endpoint URL", rpcUrlField));
		topPanel.add(createPanel("File Name", filenameField));

		// Main panel using BorderLayout to allocate space properly
		JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
		// Single-line inputs at the top (minimal space)
		mainPanel.add(topPanel, BorderLayout.NORTH);
		// Multi-line bytecode area in center (gets expanding space)
		mainPanel.add(createPanel("Deployed Bytecode / Contract Address / Transaction Hash",
				new JScrollPane(fetchBytecodeOptionTextArea)), BorderLayout.CENTER);

		dialog.add(mainPanel, BorderLayout.CENTER);
	}

	private JPanel createPanel(String labelText, JComponent component) {
		JPanel panel = new JPanel(new BorderLayout());
		JLabel label = new JLabel(labelText);
		panel.add(label, BorderLayout.NORTH);
		panel.add(component, BorderLayout.CENTER);
		return panel;
	}

	private void setupButtonsAndActions(JDialog dialog, JTextField rpcUrlField,
			JTextField filenameField, JTextArea fetchBytecodeOptionTextArea) {
		JPanel buttonPanel = new JPanel(new GridLayout(1, 3));
		JButton loadByBytecodeButton = new JButton("By Bytecode");
		JButton loadByAddressButton = new JButton("By Address");
		JButton loadByTxHashButton = new JButton("By Transaction");

		buttonPanel.add(loadByBytecodeButton);
		buttonPanel.add(loadByAddressButton);
		buttonPanel.add(loadByTxHashButton);
		dialog.add(buttonPanel, BorderLayout.SOUTH);

		loadByBytecodeButton.addActionListener(e -> {
			dialog.dispose();
			loadBytecode(fetchBytecodeOptionTextArea.getText(), filenameField.getText());
		});

		loadByAddressButton.addActionListener(e -> {
			dialog.dispose();
			String rpcUrl = rpcUrlField.getText().trim();
			saveRpcUrl(rpcUrl);  // Save RPC URL
			fetchContractBytecode(rpcUrl, fetchBytecodeOptionTextArea.getText(),
					filenameField.getText());
		});

		loadByTxHashButton.addActionListener(e -> {
			dialog.dispose();
			String rpcUrl = rpcUrlField.getText().trim();
			String txHash = fetchBytecodeOptionTextArea.getText().trim();
			saveRpcUrl(rpcUrl);  // Save RPC URL
			loadTransactionTrace(txHash, filenameField.getText(), rpcUrl);
		});
	}

	private void finalizeDialog(JDialog dialog) {
		dialog.pack();
		dialog.setLocationRelativeTo(tool.getToolFrame());
		dialog.setVisible(true);
	}

	private void fetchContractBytecode(String rpcEndpoint, String contractAddress,
			String filename) {
		// Set up the web3j service
		String errorTitle = "Failed to fetch bytecode";
		String errorMessage = "The fetched bytecode is null or empty. Please check the contract address and try again.";
		Web3j web3j = Web3j.build(new HttpService(rpcEndpoint));

		try {
			// Fetch the contract bytecode.
			EthGetCode ethGetCode = web3j.ethGetCode(contractAddress, DefaultBlockParameterName.LATEST).send();
			String bytecode = ethGetCode.getCode();

			if (bytecode == null || bytecode.isEmpty())
				showErrorPopup(errorTitle, errorMessage);
			else
				loadBytecode(bytecode, filename);

		} catch (IOException e) {
			e.printStackTrace();
			showErrorPopup(errorTitle, errorMessage);
		}
	}

	private void showErrorPopup(String title, String message) {
		JOptionPane.showMessageDialog(null, message, title, JOptionPane.ERROR_MESSAGE);
	}

	private void loadBytecode(String bytecode, String filename) {
		// Clean and prepare the bytecode and filename
		String cleanedBytecode = removePrefix(bytecode, "0x");
		String fullFilename = appendSuffix(filename, ".evm");
		try {
			// Set up the loader and load specification
			EVMLoader loader = new EVMLoader();
			LanguageCompilerSpecPair compilerSpec =
				new LanguageCompilerSpecPair("evm:256:default", "default");
			LoadSpec loadSpec = new LoadSpec(loader, 0, compilerSpec, true);

			// Load the bytecode using the custom loader
			loadAndSaveBytecode(cleanedBytecode, fullFilename, loadSpec);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String removePrefix(String input, String prefix) {
		return input.startsWith(prefix) ? input.substring(prefix.length()) : input;
	}

	private String appendSuffix(String input, String suffix) {
		return input.endsWith(suffix) ? input : input + suffix;
	}

	private void loadAndSaveBytecode(String bytecode, String filename, LoadSpec loadSpec)
			throws Exception {
		ByteProvider provider = new ByteArrayProvider(hexStringToByteArray(bytecode));
		Project project = AppInfo.getActiveProject();
		Object consumer = new Object();
		TaskMonitor monitor = TaskMonitor.DUMMY;
		MessageLog log = new MessageLog();

		ImporterSettings settings = new ImporterSettings(
			provider,
			filename,
			project,
			"",
			false,
			loadSpec,
			new ArrayList<Option>(),
			consumer,
			log,
			monitor
		);

		LoadResults<? extends DomainObject> results = loadSpec.getLoader().load(settings);

		// Save the loading results to the project
		results.save(monitor);
	}

	private byte[] hexStringToByteArray(String hexString) {
		Pattern p = Pattern.compile("[0-9a-fA-F]{2}");
		Matcher m = p.matcher(hexString);

		int count = (int) m.results().count();
		m.reset();

		byte[] byteCode = new byte[count];
		int i = 0;
		while (m.find()) {
			String hexDigit = m.group();
			byteCode[i++] = (byte) Integer.parseInt(hexDigit, 16);
		}
		return byteCode;
	}

	private void loadTransactionTrace(String txHash, String filename, String rpcUrl) {
		// Ask user what to generate
		String[] options = {"Program DB only", "Trace DB only", "Both (Recommended)"};
		int choice = JOptionPane.showOptionDialog(
			tool.getToolFrame(),
			"What would you like to generate?",
			"Generation Options",
			JOptionPane.DEFAULT_OPTION,
			JOptionPane.QUESTION_MESSAGE,
			null,
			options,
			options[2]
		);

		if (choice == JOptionPane.CLOSED_OPTION) {
			return;  // User cancelled
		}

		boolean generateProgram = (choice == 0 || choice == 2);
		boolean generateTrace = (choice == 1 || choice == 2);

		// Create and launch the task with progress dialog
		LoadTransactionTraceTask task = new LoadTransactionTraceTask(
			txHash, filename, rpcUrl, generateProgram, generateTrace);
		TaskLauncher.launch(task);
	}

	/**
	 * Task for loading transaction trace with progress reporting
	 */
	private class LoadTransactionTraceTask extends Task {
		private final String txHash;
		private final String filename;
		private final String rpcUrl;
		private final boolean generateProgram;
		private final boolean generateTrace;

		public LoadTransactionTraceTask(String txHash, String filename, String rpcUrl,
				boolean generateProgram, boolean generateTrace) {
			super("Loading Transaction Trace", true, true, true);
			this.txHash = txHash;
			this.filename = filename;
			this.rpcUrl = rpcUrl;
			this.generateProgram = generateProgram;
			this.generateTrace = generateTrace;
		}

		@Override
		public void run(TaskMonitor monitor) {
			try {
				// Initialize cache
				CacheManager.initialize();

				// Phase 1: Fetch and process data (0-30%)
				monitor.setMessage("Fetching transaction data from RPC...");
				monitor.setProgress(0);
				DataStore dataStore = fetchAndProcessTransactionData(txHash, rpcUrl, monitor);

				if (monitor.isCancelled()) {
					return;
				}

				// Phase 2: Generate Program database (30-40%)
				String programFilename = null;
				if (generateProgram) {
					monitor.setMessage("Generating Program database...");
					monitor.setProgress(30);
					programFilename = appendSuffix(filename, ".evm");
					generateProgramDatabase(txHash, programFilename, dataStore, monitor);
				}

				if (monitor.isCancelled()) {
					return;
				}

				// Phase 3: Generate Trace database (40-100%)
				if (generateTrace) {
					String traceFilename = appendSuffix(filename, ".gzf");
					String programNameForMapping = (generateProgram && generateTrace) ? programFilename : null;
					generateTraceDatabase(txHash, traceFilename, dataStore, programNameForMapping, monitor);
				}

				if (monitor.isCancelled()) {
					return;
				}

				monitor.setProgress(100);
				monitor.setMessage("Complete!");

				// Show success message on EDT
				javax.swing.SwingUtilities.invokeLater(() -> {
					StringBuilder message = new StringBuilder("Successfully generated:\n");
					if (generateProgram) {
						message.append("- Program database: ").append(filename).append(".evm\n");
					}
					if (generateTrace) {
						message.append("- Trace database: ").append(filename).append(".gzf\n");
					}
					message.append("\nTransaction: ").append(txHash);

					JOptionPane.showMessageDialog(
						tool.getToolFrame(),
						message.toString(),
						"Success",
						JOptionPane.INFORMATION_MESSAGE
					);
				});

			} catch (Exception e) {
				e.printStackTrace();
				final String errorMsg = e.getMessage();
				javax.swing.SwingUtilities.invokeLater(() -> {
					showErrorPopup("Failed to load transaction trace", "Error: " + errorMsg);
				});
			}
		}
	}

	private DataStore fetchAndProcessTransactionData(String txHash, String rpcUrl, TaskMonitor monitor) throws Exception {
		MothraLog.progress(this, "Fetching transaction data from RPC...");

		// Create RPC client
		EthereumRpcClient rpcClient = new EthereumRpcClient(rpcUrl);

		// Test connection (result stored in rpcClient; callRpc will throw if false)
		monitor.setMessage("Testing RPC connection...");
		boolean connected = rpcClient.testConnection();
		MothraLog.info(this, "RPC connection test done (valid=" + connected + ")");
		monitor.setProgress(5);

		if (monitor.isCancelled()) {
			throw new ghidra.util.exception.CancelledException();
		}

		// Create DataStore and fetch data
		DataStore dataStore = new DataStore();
		monitor.setMessage("Fetching call trace data...");
		dataStore.fetchRawData(rpcClient, txHash, monitor);
		monitor.setProgress(15);

		if (monitor.isCancelled()) {
			throw new ghidra.util.exception.CancelledException();
		}

		monitor.setMessage("Processing transaction data...");
		dataStore.processAllData(rpcClient, monitor);
		monitor.setProgress(30);

		MothraLog.info(this, "✓ Found " + dataStore.getContractList().size() + " contracts");
		MothraLog.info(this, "✓ Found " + dataStore.getInstructionSteps().size() + " instruction steps");

		return dataStore;
	}

	private void generateProgramDatabase(String txHash, String filename, DataStore dataStore,
			TaskMonitor monitor) throws Exception {
		MothraLog.progress(this, "Generating Program database...");

		ByteProvider provider = new ByteArrayProvider(hexStringToByteArray(txHash));
		Project project = AppInfo.getActiveProject();
		Object consumer = new Object();
		MessageLog log = new MessageLog();

		LanguageCompilerSpecPair compilerSpec = new LanguageCompilerSpecPair("evm:256:default", "default");
		TraceLoader loader = new TraceLoader(dataStore);
		LoadSpec loadSpec = new LoadSpec(loader, 0, compilerSpec, true);

		monitor.setMessage("Creating Program database...");

		ImporterSettings settings = new ImporterSettings(
			provider,
			filename,
			project,
			"",
			false,
			loadSpec,
			new ArrayList<Option>(),
			consumer,
			log,
			monitor
		);

		LoadResults<? extends DomainObject> results = loadSpec.getLoader().load(settings);

		monitor.setMessage("Saving Program database...");
		results.save(monitor);

		MothraLog.info(this, "✓ Program database saved: " + filename);
		monitor.setProgress(40);
	}

	private void generateTraceDatabase(String txHash, String filename, DataStore dataStore,
			String programName, TaskMonitor monitor) throws Exception {
		MothraLog.progress(this, "Generating Trace database...");

		Project project = AppInfo.getActiveProject();

		// Create temporary file for trace generation
		File tempFile = File.createTempFile("mothra_trace_", ".gzf");
		tempFile.deleteOnExit();

		try {
			// Generate trace database to temporary file
			// Pass project and program name for static mappings if both were generated
			// Progress: 40% to 95%
			TraceGeneratorCore generator = new TraceGeneratorCore(dataStore, "evm:256:default");
			generator.generateTraceDatabase(txHash, tempFile.getAbsolutePath(), project, programName, monitor);

			if (monitor.isCancelled()) {
				return;
			}

			MothraLog.info(this, "  → Importing trace into project...");
			monitor.setMessage("Importing trace into project...");
			monitor.setProgress(96);

			// Import the trace file into Ghidra project
			DomainFolder rootFolder = project.getProjectData().getRootFolder();
			DomainFile domainFile = rootFolder.createFile(filename, tempFile, monitor);

			MothraLog.info(this, "✓ Trace database imported: " + domainFile.getPathname());
			monitor.setProgress(98);

			// Open the trace in Ghidra on the Swing EDT to avoid deadlock.
			// The modal task dialog blocks the EDT, so any synchronous Swing
			// call from this background thread would deadlock.
			if (domainFile != null) {
				monitor.setMessage("Opening trace in Ghidra...");
				final DomainFile df = domainFile;
				javax.swing.SwingUtilities.invokeLater(() -> {
					tool.acceptDomainFiles(new DomainFile[] { df });
					MothraLog.info(this, "✓ Trace database opened in Ghidra");
				});
			}
			monitor.setProgress(100);

		} finally {
			// Clean up temporary file
			if (tempFile.exists()) {
				tempFile.delete();
			}
		}
	}
}
