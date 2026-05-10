package com.comint;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.extension.ExtensionUnloadingHandler;

import com.comint.codec.CodecRegistry;
import com.comint.codec.GraphQLCodec;
import com.comint.codec.GrpcWebCodec;
import com.comint.codec.MessagePackCodec;
import com.comint.codec.ProtobufCodec;
import com.comint.codec.WebSocketCodec;
import com.comint.bridge.ComintWsBridge;
import com.comint.editor.ComintRequestEditorProvider;
import com.comint.editor.ComintResponseEditorProvider;
import com.comint.handler.ComintContextMenuProvider;
import com.comint.handler.ComintHttpHandler;
import com.comint.handler.ComintWebSocketHandler;
import com.comint.scanner.ComintInsertionPointProvider;
import com.comint.ui.ComintTrafficPanel;

import javax.swing.SwingUtilities;
import java.util.concurrent.atomic.AtomicInteger;

public class ComintExtension implements BurpExtension, ExtensionUnloadingHandler {

    private MontoyaApi api;
    private CodecRegistry codecRegistry;
    private ComintTrafficPanel trafficPanel;
    private ComintWsBridge wsBridge;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        try {
            api.extension().setName("COMINT");
        } catch (Throwable t) {
            // setName failure is non-fatal — keep going.
        }

        codecRegistry = new CodecRegistry();
        // Order matters: more specific codecs (gRPC-Web before generic Protobuf) come first.
        try { codecRegistry.register(new GrpcWebCodec()); } catch (Throwable t) { logErr("register GrpcWebCodec: " + safeMsg(t)); }
        try { codecRegistry.register(new ProtobufCodec()); } catch (Throwable t) { logErr("register ProtobufCodec: " + safeMsg(t)); }
        try { codecRegistry.register(new MessagePackCodec()); } catch (Throwable t) { logErr("register MessagePackCodec: " + safeMsg(t)); }
        try { codecRegistry.register(new GraphQLCodec()); } catch (Throwable t) { logErr("register GraphQLCodec: " + safeMsg(t)); }

        WebSocketCodec wsCodec = new WebSocketCodec();
        AtomicInteger sharedCounter = new AtomicInteger();

        // WS Bridge — construct (but don't start) before the Traffic panel.
        // Construction order is forced by a chicken-and-egg: the panel needs the
        // bridge instance for its toolbar, and the bridge needs the panel as its
        // traffic listener (Bug 1+2 fix). Resolved by:
        //   1. construct bridge with null listener
        //   2. construct panel — captures bridge ref for toolbar
        //   3. inject panel as listener via bridge.setTrafficListener
        //   4. bridge.start() — handler captures the now-set listener
        try {
            this.wsBridge = new ComintWsBridge(api, null, sharedCounter, codecRegistry);
        } catch (Throwable t) {
            logErr("WS bridge construct failed: " + safeMsg(t));
        }

        // Traffic panel must be created on the EDT.
        try {
            final ComintWsBridge bridgeRef = this.wsBridge;
            if (SwingUtilities.isEventDispatchThread()) {
                this.trafficPanel = new ComintTrafficPanel(api, codecRegistry, bridgeRef);
            } else {
                final ComintTrafficPanel[] holder = new ComintTrafficPanel[1];
                SwingUtilities.invokeAndWait(() -> holder[0] = new ComintTrafficPanel(api, codecRegistry, bridgeRef));
                this.trafficPanel = holder[0];
            }
            api.userInterface().registerSuiteTab("COMINT Traffic", trafficPanel);
        } catch (Throwable t) {
            logErr("registerSuiteTab failed: " + safeMsg(t));
            // Continue without the traffic panel — codecs/editors still work.
        }

        // Inject panel as bridge listener and start the bridge.
        try {
            if (wsBridge != null) {
                if (trafficPanel != null) wsBridge.setTrafficListener(trafficPanel);
                wsBridge.start();
            }
        } catch (Throwable t) {
            logErr("WS bridge start failed: " + safeMsg(t));
        }

        try {
            api.userInterface().registerHttpRequestEditorProvider(
                    new ComintRequestEditorProvider(api, codecRegistry));
        } catch (Throwable t) {
            logErr("registerHttpRequestEditorProvider failed: " + safeMsg(t));
        }
        try {
            api.userInterface().registerHttpResponseEditorProvider(
                    new ComintResponseEditorProvider(api, codecRegistry));
        } catch (Throwable t) {
            logErr("registerHttpResponseEditorProvider failed: " + safeMsg(t));
        }
        // HTTP handler → traffic panel.
        try {
            ComintHttpHandler httpHandler = new ComintHttpHandler(api, codecRegistry, trafficPanel, sharedCounter, wsBridge);
            api.http().registerHttpHandler(httpHandler);
        } catch (Throwable t) {
            logErr("registerHttpHandler failed: " + safeMsg(t));
        }

        // WebSocket handler → traffic panel.
        try {
            ComintWebSocketHandler wsHandler = new ComintWebSocketHandler(
                    api, codecRegistry, wsCodec, trafficPanel, sharedCounter);
            api.websockets().registerWebSocketCreatedHandler(wsHandler);
        } catch (Throwable t) {
            logErr("registerWebSocketCreatedHandler failed: " + safeMsg(t));
        }

        // Scanner insertion-point provider — exposes decoded fields as scan targets.
        try {
            api.scanner().registerInsertionPointProvider(
                    new ComintInsertionPointProvider(api, codecRegistry));
        } catch (Throwable t) {
            logErr("registerInsertionPointProvider failed: " + safeMsg(t));
        }

        // WS-8: right-click context menu in any message editor — RawEditor doesn't
        // inherit Burp's native menu, so this provides COMINT's Send-to options.
        try {
            api.userInterface().registerContextMenuItemsProvider(
                    new ComintContextMenuProvider(api, codecRegistry));
        } catch (Throwable t) {
            logErr("registerContextMenuItemsProvider failed: " + safeMsg(t));
        }

        try {
            api.extension().registerUnloadingHandler(this);
        } catch (Throwable t) {
            logErr("registerUnloadingHandler failed: " + safeMsg(t));
        }

        try {
            api.logging().logToOutput("COMINT loaded. Registered codecs: " + java.util.stream.Stream.concat(codecRegistry.names().stream(), java.util.stream.Stream.of("WebSocket")).toList());
        } catch (Throwable ignored) {}
    }

    @Override
    public void extensionUnloaded() {
        // Tear down the WS bridge first so its threads/sockets don't outlive the extension.
        try { if (trafficPanel != null) trafficPanel.teardownBridgeStatusTimer(); } catch (Throwable ignored) {}
        try { if (wsBridge != null) wsBridge.shutdown(); } catch (Throwable ignored) {}
        try {
            if (api != null) api.logging().logToOutput("COMINT unloaded.");
        } catch (Throwable ignored) {}
    }

    private void logErr(String msg) {
        try { if (api != null) api.logging().logToError("COMINT init: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
