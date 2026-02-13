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

import java.lang.reflect.*;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginEventListener;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.trace.model.Trace;
import ghidra.util.HelpLocation;
import mothra.util.MothraLog;

/**
 * EvmStatePlugin - Debugger plugin for viewing EVM execution state
 *
 * This plugin displays four panels showing EVM execution data:
 * - Calldata: Transaction input data
 * - Memory: EVM memory state
 * - Stack: EVM stack contents
 * - Storage: Contract storage key-value pairs
 *
 * The plugin listens to TraceActivatedPluginEvent to automatically update when
 * the snapshot changes. It reads data from RAM at:
 * - 0x40000000: Calldata
 * - 0x50000000: Memory
 * - 0x60000000: Stack
 * - 0x70000000: Storage
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.DEBUGGER,
    shortDescription = "EVM State Viewer",
    description = "Displays EVM execution state (calldata, memory, stack, storage) from trace snapshots"
)
//@formatter:on
public class EvmStatePlugin extends Plugin {

    // Event class names for dynamic loading (to avoid compile-time dependency on Debugger module)
    private static final String TRACE_ACTIVATED_EVENT_CLASS =
        "ghidra.app.plugin.core.debug.event.TraceActivatedPluginEvent";
    private static final String TRACE_CLOSED_EVENT_CLASS =
        "ghidra.app.plugin.core.debug.event.TraceClosedPluginEvent";

    private EvmStateProvider provider;
    private Trace currentTrace;
    private long currentSnap = -1;

    // Service for accessing trace manager (obtained dynamically)
    private Object traceManagerService;

    // Event classes loaded via reflection
    private Class<? extends PluginEvent> traceActivatedEventClass;
    private Class<? extends PluginEvent> traceClosedEventClass;

    // Event listener (separate instance since Plugin.eventSent is final)
    private PluginEventListener eventListener;

    public EvmStatePlugin(PluginTool tool) {
        super(tool);

        try {
            provider = new EvmStateProvider(tool, this);
            tool.addComponentProvider(provider, false);
            buildShowWindowAction();

            // Register for debugger events (using reflection to avoid compile-time dependency)
            registerEventListeners();

            MothraLog.info(this, "EvmStatePlugin initialized successfully");
        } catch (Exception e) {
            MothraLog.error(this, "ERROR: Failed to initialize EvmStatePlugin: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Register for debugger events using reflection to avoid compile-time dependency
     */
    @SuppressWarnings("unchecked")
    private void registerEventListeners() {
        // Create event listener (separate instance since Plugin.eventSent is final)
        eventListener = event -> handlePluginEvent(event);

        try {
            // Load TraceActivatedPluginEvent class
            traceActivatedEventClass =
                (Class<? extends PluginEvent>) Class.forName(TRACE_ACTIVATED_EVENT_CLASS);
            tool.addEventListener(traceActivatedEventClass, eventListener);
            MothraLog.info(this, "Registered listener for TraceActivatedPluginEvent");
        } catch (ClassNotFoundException e) {
            MothraLog.debug(this, "TraceActivatedPluginEvent not available (Debugger module not loaded)");
        }

        try {
            // Load TraceClosedPluginEvent class
            traceClosedEventClass =
                (Class<? extends PluginEvent>) Class.forName(TRACE_CLOSED_EVENT_CLASS);
            tool.addEventListener(traceClosedEventClass, eventListener);
            MothraLog.info(this, "Registered listener for TraceClosedPluginEvent");
        } catch (ClassNotFoundException e) {
            MothraLog.debug(this, "TraceClosedPluginEvent not available (Debugger module not loaded)");
        }
    }

    /**
     * Unregister event listeners
     */
    private void unregisterEventListeners() {
        if (eventListener == null) {
            return;
        }

        try {
            if (traceActivatedEventClass != null) {
                // Use reflection to call removeEventListener since it may not be accessible
                Method removeMethod = tool.getClass().getMethod("removeEventListener",
                    Class.class, PluginEventListener.class);
                removeMethod.invoke(tool, traceActivatedEventClass, eventListener);
            }
            if (traceClosedEventClass != null) {
                Method removeMethod = tool.getClass().getMethod("removeEventListener",
                    Class.class, PluginEventListener.class);
                removeMethod.invoke(tool, traceClosedEventClass, eventListener);
            }
        } catch (Exception e) {
            MothraLog.debug(this, "Could not unregister event listeners: " + e.getMessage());
        }
    }

    /**
     * Handle plugin events from the event listener
     */
    private void handlePluginEvent(PluginEvent event) {
        if (traceActivatedEventClass != null && traceActivatedEventClass.isInstance(event)) {
            handleTraceActivatedEvent(event);
        } else if (traceClosedEventClass != null && traceClosedEventClass.isInstance(event)) {
            handleTraceClosedEvent(event);
        }
    }

    /**
     * Handle TraceActivatedPluginEvent - called when snap/coordinates change
     */
    private void handleTraceActivatedEvent(PluginEvent event) {
        try {
            // Get coordinates from the event using reflection
            Method getActiveCoordinatesMethod = event.getClass().getMethod("getActiveCoordinates");
            Object coords = getActiveCoordinatesMethod.invoke(event);

            if (coords != null) {
                handleCoordinatesChanged(coords);
            }
        } catch (Exception e) {
            MothraLog.error(this, "Error handling TraceActivatedPluginEvent: " + e.getMessage());
        }
    }

    /**
     * Handle TraceClosedPluginEvent - called when a trace is closed
     */
    private void handleTraceClosedEvent(PluginEvent event) {
        try {
            // Get trace from the event using reflection
            Method getTraceMethod = event.getClass().getMethod("getTrace");
            Trace closedTrace = (Trace) getTraceMethod.invoke(event);

            if (closedTrace != null && closedTrace == currentTrace) {
                currentTrace = null;
                currentSnap = -1;
                if (provider != null) {
                    provider.clearDisplay();
                }
                MothraLog.info(this, "Current trace was closed, cleared display");
            }
        } catch (Exception e) {
            MothraLog.error(this, "Error handling TraceClosedPluginEvent: " + e.getMessage());
        }
    }

    @Override
    protected void init() {
        super.init();
        // Try to connect to trace manager after plugin is fully initialized
        initializeTraceManagerService();
        // Get initial state
        refreshFromTraceManager();
    }

    /**
     * Initialize the trace manager service
     */
    private void initializeTraceManagerService() {
        try {
            // Try to get DebuggerTraceManagerService
            Class<?> serviceClass = Class.forName("ghidra.app.services.DebuggerTraceManagerService");
            traceManagerService = tool.getService(serviceClass);

            if (traceManagerService != null) {
                MothraLog.info(this, "DebuggerTraceManagerService found");
            }
        } catch (ClassNotFoundException e) {
            // Debugger module not loaded
        } catch (Exception e) {
            MothraLog.error(this, "Error initializing trace manager service: " + e.getMessage());
        }
    }

    /**
     * Refresh state from trace manager service
     */
    public void refreshFromTraceManager() {
        if (traceManagerService == null) {
            initializeTraceManagerService();
        }

        if (traceManagerService == null) {
            MothraLog.debug(this, "Trace manager service not available");
            return;
        }

        try {
            // Get current coordinates using reflection
            Method getCurrentMethod = traceManagerService.getClass().getMethod("getCurrent");
            Object coords = getCurrentMethod.invoke(traceManagerService);

            if (coords != null) {
                handleCoordinatesChanged(coords);
            }
        } catch (Exception e) {
            MothraLog.error(this, "Error getting current trace: " + e.getMessage());
        }
    }

    /**
     * Handle coordinates changed - extract trace and snap, update display
     */
    private void handleCoordinatesChanged(Object coords) {
        if (coords == null) {
            return;
        }

        try {
            // Extract trace and snap from coordinates
            Method getTraceMethod = coords.getClass().getMethod("getTrace");
            Method getSnapMethod = coords.getClass().getMethod("getSnap");

            Trace trace = (Trace) getTraceMethod.invoke(coords);
            Long snap = (Long) getSnapMethod.invoke(coords);

            if (trace != null) {
                currentTrace = trace;
                currentSnap = snap != null ? snap : 0;
                MothraLog.info(this, "Coordinates changed: trace=" + trace.getName() + ", snap=" + currentSnap);
                updateStateDisplay();
            }
        } catch (Exception e) {
            MothraLog.error(this, "Error handling coordinates change: " + e.getMessage());
        }
    }

    private void buildShowWindowAction() {
        DockingAction show = new DockingAction("Show EVM State", getName()) {
            @Override
            public void actionPerformed(ActionContext ctx) {
                provider.setVisible(true);
                provider.toFront();
                // Refresh data when showing the window
                refreshFromTraceManager();
            }
        };

        show.setMenuBarData(new MenuData(new String[] { "Window", "EVM State Viewer" }));
        show.setDescription("Display EVM execution state (calldata, memory, stack, storage)");
        show.setHelpLocation(new HelpLocation("EvmStateViewer", "Overview"));

        tool.addAction(show);
    }

    @Override
    public void serviceAdded(Class<?> interfaceClass, Object service) {
        super.serviceAdded(interfaceClass, service);

        // Check if the added service is the trace manager
        if (interfaceClass.getName().contains("DebuggerTraceManagerService") ||
            interfaceClass.getName().contains("TraceManager")) {
            MothraLog.info(this, "TraceManager service added: " + interfaceClass.getName());
            traceManagerService = service;
            refreshFromTraceManager();
        }
    }

    @Override
    public void serviceRemoved(Class<?> interfaceClass, Object service) {
        super.serviceRemoved(interfaceClass, service);

        if (service == traceManagerService) {
            traceManagerService = null;
            currentTrace = null;
            currentSnap = -1;
            if (provider != null) {
                provider.clearDisplay();
            }
        }
    }

    @Override
    public void dispose() {
        unregisterEventListeners();
        if (provider != null) {
            tool.removeComponentProvider(provider);
        }
        super.dispose();
    }

    /**
     * Update the state display with current trace and snapshot
     */
    private void updateStateDisplay() {
        if (provider != null && currentTrace != null) {
            provider.updateState(currentTrace, currentSnap);
        }
    }

    /**
     * Get the current trace
     */
    public Trace getCurrentTrace() {
        return currentTrace;
    }

    /**
     * Get the current snapshot number
     */
    public long getCurrentSnap() {
        return currentSnap;
    }

    /**
     * Manually set trace and snapshot (can be called from provider)
     */
    public void setTraceAndSnap(Trace trace, long snap) {
        this.currentTrace = trace;
        this.currentSnap = snap;
        updateStateDisplay();
    }

    /**
     * Refresh the display with current state
     */
    public void refresh() {
        refreshFromTraceManager();
    }
}
