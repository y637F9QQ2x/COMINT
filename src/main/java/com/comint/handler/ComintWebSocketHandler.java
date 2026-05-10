package com.comint.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.websocket.BinaryMessage;
import burp.api.montoya.websocket.BinaryMessageAction;
import burp.api.montoya.websocket.Direction;
import burp.api.montoya.websocket.MessageHandler;
import burp.api.montoya.websocket.TextMessage;
import burp.api.montoya.websocket.TextMessageAction;
import burp.api.montoya.websocket.WebSocketCreated;
import burp.api.montoya.websocket.WebSocketCreatedHandler;

import com.comint.codec.CodecRegistry;
import com.comint.codec.WebSocketCodec;
import com.comint.ui.ComintTrafficEntry;
import com.comint.ui.ComintTrafficListener;

import java.util.concurrent.atomic.AtomicInteger;

/**
 * Pass-through WebSocket handler. Per WS, registers a fresh
 * {@link MessageHandler} bound to the upgrade request so concurrent WebSockets
 * don't share state.
 */
public class ComintWebSocketHandler implements WebSocketCreatedHandler {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;
    private final WebSocketCodec wsCodec;
    private final ComintTrafficListener listener;
    private final AtomicInteger entryCounter;

    public ComintWebSocketHandler(MontoyaApi api,
                                  CodecRegistry codecRegistry,
                                  WebSocketCodec wsCodec,
                                  ComintTrafficListener listener,
                                  AtomicInteger sharedCounter) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.wsCodec = wsCodec;
        this.listener = listener;
        this.entryCounter = sharedCounter != null ? sharedCounter : new AtomicInteger();
    }

    @Override
    public void handleWebSocketCreated(WebSocketCreated webSocketCreated) {
        try {
            if (webSocketCreated == null) return;
            HttpRequest upgrade = null;
            try { upgrade = webSocketCreated.upgradeRequest(); } catch (Throwable ignored) {}
            // R25 fix: capture the originating Burp tool at creation time so every
            // subsequent message on this connection inherits the same Source label
            // (Proxy / Repeater / Intruder / etc.) instead of the generic "WebSocket".
            // The COMINT bridge's outbound connections use java.net.http.WebSocket
            // directly and never reach this handler, so anything we see here came
            // through Burp's WebSocket subsystem.
            String connectionSource = "WebSocket";
            try {
                ToolSource ts = webSocketCreated.toolSource();
                String label = sourceLabelFor(ts);
                if (label != null && !label.isEmpty()) connectionSource = label;
            } catch (Throwable ignored) {}
            try {
                webSocketCreated.webSocket().registerMessageHandler(new PerWsHandler(upgrade, connectionSource));
            } catch (Throwable t) {
                logErr("registerMessageHandler failed: " + safeMsg(t));
                return;
            }
            try {
                String url = "";
                if (upgrade != null) {
                    try { url = String.valueOf(upgrade.url()); } catch (Throwable ignored) {}
                }
                api.logging().logToOutput("COMINT: WebSocket created for " + url);
            } catch (Throwable ignored) {}
        } catch (Throwable t) {
            logErr("handleWebSocketCreated error: " + safeMsg(t));
        }
    }

    private final class PerWsHandler implements MessageHandler {
        private final HttpRequest upgradeRequest;
        private final String wsHost;
        private final String wsUrl;
        private final String wsProtocol;
        /** R25 fix: originating tool captured at WebSocket-created time. */
        private final String wsSource;

        PerWsHandler(HttpRequest upgrade, String source) {
            this.upgradeRequest = upgrade;
            String host = "";
            String url = "";
            // WS-10: every WebSocket-related entry (handshake + messages) is just "WS".
            // The transport (ws:// vs wss://) is reflected by the upgrade request's
            // HttpService.secure() — preserved on the synthetic request via WS-9.
            String proto = "WS";
            if (upgrade != null) {
                try {
                    HttpService svc = upgrade.httpService();
                    if (svc != null) {
                        host = svc.host() == null ? "" : svc.host();
                    }
                } catch (Throwable ignored) {}
                try {
                    String u = upgrade.url();
                    if (u != null) url = u;
                } catch (Throwable ignored) {}
            }
            this.wsHost = host;
            this.wsUrl = url;
            this.wsProtocol = proto;
            this.wsSource = (source == null || source.isEmpty()) ? "WebSocket" : source;
        }

        @Override
        public TextMessageAction handleTextMessage(TextMessage textMessage) {
            try {
                if (textMessage != null && listener != null) {
                    String payload = "";
                    int len = 0;
                    Direction dir = Direction.CLIENT_TO_SERVER;
                    try { payload = textMessage.payload(); if (payload == null) payload = ""; } catch (Throwable ignored) {}
                    try { len = payload.length(); } catch (Throwable ignored) {}
                    try { dir = textMessage.direction(); if (dir == null) dir = Direction.CLIENT_TO_SERVER; } catch (Throwable ignored) {}

                    String codecName = detectTextCodec(payload);
                    ComintTrafficEntry entry = ComintTrafficEntry.builder()
                            .id(entryCounter.incrementAndGet())
                            .timestamp(System.currentTimeMillis())
                            .kind(ComintTrafficEntry.Kind.WS_TEXT)
                            .host(wsHost)
                            .method(dir == Direction.CLIENT_TO_SERVER ? "WS →" : "WS ←")
                            .url(wsUrl)
                            .protocol(wsProtocol)
                            .codec(codecName)
                            .length(len)
                            .wsUpgradeRequest(upgradeRequest)
                            .wsTextPayload(payload)
                            .wsDirection(dir)
                            .source(wsSource)
                            .build();
                    try { listener.onEntry(entry); } catch (Throwable t) { logErr("listener.onEntry (ws text): " + safeMsg(t)); }
                }
            } catch (Throwable t) {
                logErr("handleTextMessage error: " + safeMsg(t));
            }
            try {
                return TextMessageAction.continueWith(textMessage);
            } catch (Throwable t) {
                logErr("TextMessageAction.continueWith: " + safeMsg(t));
                return TextMessageAction.continueWith(textMessage == null ? "" : textMessage.payload());
            }
        }

        @Override
        public BinaryMessageAction handleBinaryMessage(BinaryMessage binaryMessage) {
            try {
                if (binaryMessage != null && listener != null) {
                    byte[] bytes = new byte[0];
                    int len = 0;
                    Direction dir = Direction.CLIENT_TO_SERVER;
                    try {
                        if (binaryMessage.payload() != null) {
                            byte[] b = binaryMessage.payload().getBytes();
                            if (b != null) bytes = b;
                        }
                    } catch (Throwable ignored) {}
                    len = bytes.length;
                    try { dir = binaryMessage.direction(); if (dir == null) dir = Direction.CLIENT_TO_SERVER; } catch (Throwable ignored) {}

                    String codecName = detectBinaryCodec(bytes);
                    ComintTrafficEntry entry = ComintTrafficEntry.builder()
                            .id(entryCounter.incrementAndGet())
                            .timestamp(System.currentTimeMillis())
                            .kind(ComintTrafficEntry.Kind.WS_BINARY)
                            .host(wsHost)
                            .method(dir == Direction.CLIENT_TO_SERVER ? "WS →" : "WS ←")
                            .url(wsUrl)
                            .protocol(wsProtocol)
                            .codec(codecName)
                            .length(len)
                            .wsUpgradeRequest(upgradeRequest)
                            .wsBinaryPayload(bytes)
                            .wsDirection(dir)
                            .source(wsSource)
                            .build();
                    try { listener.onEntry(entry); } catch (Throwable t) { logErr("listener.onEntry (ws binary): " + safeMsg(t)); }
                }
            } catch (Throwable t) {
                logErr("handleBinaryMessage error: " + safeMsg(t));
            }
            try {
                return BinaryMessageAction.continueWith(binaryMessage);
            } catch (Throwable t) {
                logErr("BinaryMessageAction.continueWith: " + safeMsg(t));
                try {
                    return BinaryMessageAction.continueWith(binaryMessage.payload());
                } catch (Throwable ignored) {
                    return BinaryMessageAction.continueWith(burp.api.montoya.core.ByteArray.byteArray(new byte[0]));
                }
            }
        }

        @Override
        public void onClose() {}

        private String detectTextCodec(String payload) {
            if (payload == null || payload.isEmpty()) return "None";
            try {
                String decoded = wsCodec.decodeText(payload);
                if (decoded == null) return "None";
                if (decoded.contains("\"kind\" : \"graphql_ws\"")
                        || decoded.contains("\"kind\":\"graphql_ws\"")) return "GraphQL-WS";
                if (decoded.contains("\"kind\" : \"json\"")
                        || decoded.contains("\"kind\":\"json\"")) return "JSON";
                return "Text";
            } catch (Throwable t) {
                return "None";
            }
        }

        private String detectBinaryCodec(byte[] data) {
            if (data == null || data.length == 0) return "None";
            try {
                String decoded = wsCodec.decodeBinary(data);
                if (decoded == null) return "None";
                if (decoded.contains("\"kind\" : \"msgpack\"")
                        || decoded.contains("\"kind\":\"msgpack\"")) return "MessagePack";
                if (decoded.contains("\"kind\" : \"protobuf\"")
                        || decoded.contains("\"kind\":\"protobuf\"")) return "Protobuf";
                return "Binary";
            } catch (Throwable t) {
                return "None";
            }
        }
    }

    /** R25 fix: same mapping as ComintHttpHandler.sourceLabelFor — duplicated
     *  intentionally to keep these handlers independent of each other. */
    private static String sourceLabelFor(ToolSource ts) {
        if (ts == null) return "";
        ToolType type;
        try { type = ts.toolType(); } catch (Throwable t) { return ""; }
        if (type == null) return "";
        if (type == ToolType.PROXY) return "Proxy";
        if (type == ToolType.REPEATER) return "Repeater";
        if (type == ToolType.INTRUDER) return "Intruder";
        if (type == ToolType.SCANNER) return "Scanner";
        if (type == ToolType.EXTENSIONS) return "Extension";
        try {
            String name = type.toolName();
            return name == null ? "" : name;
        } catch (Throwable t) {
            return "";
        }
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT WS: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
