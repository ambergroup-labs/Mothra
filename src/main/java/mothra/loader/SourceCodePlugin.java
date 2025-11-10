package mothra.loader;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;

//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "EVM Contract Source Viewer",
    description = "Displays verified Solidity source code for EVM contracts"
)
//@formatter:on
public class SourceCodePlugin extends ProgramPlugin {

    private SourceCodeProvider provider;

    public SourceCodePlugin(PluginTool tool) {
        super(tool);

        // create and register our pane, but keep it hidden until the user asks for it
        provider = new SourceCodeProvider(tool, this);
        tool.addComponentProvider(provider, false);

        buildShowWindowAction();
    }

    private void buildShowWindowAction() {
        DockingAction show = new DockingAction("Show Contract Source", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                provider.setVisible(true); // shows the dockable window
                provider.toFront();
            }
        };
        show.setMenuBarData(new MenuData(new String[] { "Window", "EVM Contract Source" }));
        show.setDescription("Open a dockable panel that shows verified Solidity " +
                "for the contract under the cursor.");
        show.setHelpLocation(new HelpLocation("EvmSourceViewer", "Overview"));
        tool.addAction(show);
    }

    @Override
    public void dispose() {
        tool.removeComponentProvider(provider);
        super.dispose();
    }

    /**
     * Handle program location changes from the Listing window.
     * This method is called when the user moves the cursor or selects text in the
     * Listing.
     */
    @Override
    public void locationChanged(ProgramLocation location) {
        super.locationChanged(location);

        // Forward the location change to our provider
        if (provider != null) {
            provider.programLocationChanged(location);
        }
    }

    /**
     * Handle selection changes from the Listing window.
     * This method is called when the user selects a range of addresses.
     */
    @Override
    public void selectionChanged(ProgramSelection selection) {
        super.selectionChanged(selection);

        // Forward the selection change to our provider
        if (provider != null) {
            provider.selectionChanged(selection);
        }
    }

    /**
     * Handle program activation events.
     * This method is called when a new program becomes active.
     */
    @Override
    public void programActivated(ghidra.program.model.listing.Program program) {
        super.programActivated(program);

        // Refresh the provider when the program changes
        if (provider != null) {
            System.out.println(
                    "DEBUG: SourceCodePlugin - program activated: " + (program != null ? program.getName() : "null"));
            provider.initializeDisplay();
        }
    }
}