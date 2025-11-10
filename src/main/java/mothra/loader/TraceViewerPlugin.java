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
    shortDescription = "EVM Trace Viewer",
    description = "Simple and clean EVM trace viewing interface"
)
//@formatter:on
public class TraceViewerPlugin extends ProgramPlugin {

    private TraceViewerProvider provider;

    public TraceViewerPlugin(PluginTool tool) {
        super(tool);

        try {
            provider = new TraceViewerProvider(tool, this);

            tool.addComponentProvider(provider, false);

            buildShowWindowAction();

        } catch (Exception e) {
            System.err.println("ERROR: Failed to initialize TraceViewerPlugin: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void buildShowWindowAction() {

        DockingAction show = new DockingAction("Show Trace Viewer", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                provider.setVisible(true);
                provider.toFront();
            }
        };

        show.setMenuBarData(new MenuData(new String[] { "Window", "Trace Viewer" }));

        show.setDescription("Open a clean and simple trace viewing interface for EVM contracts");
        show.setHelpLocation(new HelpLocation("TraceViewer", "Overview"));

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

        if (provider != null) {
            provider.loadTransactionTrace();
        }
    }
}
