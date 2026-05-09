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
import com.comint.editor.ComintRequestEditorProvider;
import com.comint.editor.ComintResponseEditorProvider;
import com.comint.editor.ComintWebSocketMessageEditorProvider;
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

        // Traffic panel must be created on the EDT.
        try {
            if (SwingUtilities.isEventDispatchThread()) {
                this.trafficPanel = new ComintTrafficPanel(api, codecRegistry);
            } else {
                final ComintTrafficPanel[] holder = new ComintTrafficPanel[1];
                SwingUtilities.invokeAndWait(() -> holder[0] = new ComintTrafficPanel(api, codecRegistry));
                this.trafficPanel = holder[0];
            }
            api.userInterface().registerSuiteTab("COMINT Traffic", trafficPanel);
        } catch (Throwable t) {
            logErr("registerSuiteTab failed: " + safeMsg(t));
            // Continue without the traffic panel — codecs/editors still work.
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
        try {
            api.userInterface().registerWebSocketMessageEditorProvider(
                    new ComintWebSocketMessageEditorProvider(api, wsCodec));
        } catch (Throwable t) {
            logErr("registerWebSocketMessageEditorProvider failed: " + safeMsg(t));
        }

        // HTTP handler → traffic panel.
        try {
            ComintHttpHandler httpHandler = new ComintHttpHandler(api, codecRegistry, trafficPanel, sharedCounter);
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

        try {
            api.extension().registerUnloadingHandler(this);
        } catch (Throwable t) {
            logErr("registerUnloadingHandler failed: " + safeMsg(t));
        }

        try {
            api.logging().logToOutput("COMINT loaded. Registered codecs: " + codecRegistry.names());
        } catch (Throwable ignored) {}
    }

    @Override
    public void extensionUnloaded() {
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
