package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.contextmenu.WebSocketMessage;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;

import com.comint.codec.WebSocketCodec;

import java.awt.Component;
import java.nio.charset.StandardCharsets;

public class ComintWebSocketMessageEditor implements ExtensionProvidedWebSocketMessageEditor {

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;

    private final MontoyaApi api;
    private final WebSocketCodec codec;
    private final RawEditor rawEditor;

    private WebSocketMessage currentMessage;
    private boolean treatAsBinary = false;

    public ComintWebSocketMessageEditor(MontoyaApi api, WebSocketCodec codec, EditorCreationContext creationContext) {
        this.api = api;
        this.codec = codec;
        this.rawEditor = creationContext != null && creationContext.editorMode() == EditorMode.READ_ONLY
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();
    }

    @Override
    public ByteArray getMessage() {
        if (currentMessage == null) {
            return ByteArray.byteArray(new byte[0]);
        }
        if (!isModified()) {
            try {
                ByteArray p = currentMessage.payload();
                return p == null ? ByteArray.byteArray(new byte[0]) : p;
            } catch (Throwable t) {
                logErr("getMessage(payload) failed: " + safeMsg(t));
                return ByteArray.byteArray(new byte[0]);
            }
        }
        try {
            ByteArray contents = rawEditor.getContents();
            String edited = contents == null ? "" : contents.toString();
            if (treatAsBinary) {
                byte[] reEncoded = codec.encodeBinary(edited);
                if (reEncoded == null) reEncoded = new byte[0];
                return ByteArray.byteArray(reEncoded);
            }
            String reEncoded = codec.encodeText(edited);
            if (reEncoded == null) reEncoded = "";
            return ByteArray.byteArray(reEncoded.getBytes(StandardCharsets.UTF_8));
        } catch (Throwable t) {
            logErr("getMessage re-encode error: " + safeMsg(t));
            try {
                ByteArray p = currentMessage.payload();
                return p == null ? ByteArray.byteArray(new byte[0]) : p;
            } catch (Throwable ignored) {
                return ByteArray.byteArray(new byte[0]);
            }
        }
    }

    @Override
    public void setMessage(WebSocketMessage message) {
        this.currentMessage = message;
        try {
            if (message == null) {
                rawEditor.setContents(ByteArray.byteArray(new byte[0]));
                return;
            }
            ByteArray payload = message.payload();
            byte[] bytes = (payload == null) ? new byte[0] : payload.getBytes();
            if (bytes == null) bytes = new byte[0];
            if (bytes.length > MAX_PAYLOAD_BYTES) {
                rawEditor.setContents(ByteArray.byteArray(("/* COMINT WebSocket: payload too large (" + bytes.length + " bytes) */").getBytes(StandardCharsets.UTF_8)));
                return;
            }
            this.treatAsBinary = looksBinary(bytes);
            String decoded;
            try {
                if (treatAsBinary) {
                    decoded = codec.decodeBinary(bytes);
                } else {
                    decoded = codec.decodeText(new String(bytes, StandardCharsets.UTF_8));
                }
                if (decoded == null) decoded = "";
            } catch (Throwable t) {
                decoded = "/* COMINT WebSocket decode error: " + safeMsg(t) + " */";
            }
            rawEditor.setContents(ByteArray.byteArray(decoded.getBytes(StandardCharsets.UTF_8)));
        } catch (Throwable t) {
            logErr("setMessage error: " + safeMsg(t));
            try {
                rawEditor.setContents(ByteArray.byteArray(("/* COMINT WebSocket error: " + safeMsg(t) + " */").getBytes(StandardCharsets.UTF_8)));
            } catch (Throwable ignored) {}
        }
    }

    @Override
    public boolean isEnabledFor(WebSocketMessage message) {
        try {
            if (message == null) return false;
            ByteArray payload;
            try {
                payload = message.payload();
            } catch (Throwable t) {
                return false;
            }
            if (payload == null) return false;
            int len;
            try {
                len = payload.length();
            } catch (Throwable t) {
                return false;
            }
            return len > 0;
        } catch (Throwable t) {
            logErr("isEnabledFor (websocket) error: " + safeMsg(t));
            return false;
        }
    }

    @Override
    public String caption() {
        return "COMINT - WebSocket";
    }

    @Override
    public Component uiComponent() {
        return rawEditor.uiComponent();
    }

    @Override
    public Selection selectedData() {
        try {
            return rawEditor.selection().orElse(null);
        } catch (Throwable t) {
            return null;
        }
    }

    @Override
    public boolean isModified() {
        try {
            return rawEditor.isModified();
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean looksBinary(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        // Heuristic: non-printable byte (other than tab/newline/CR) => binary.
        int sample = Math.min(bytes.length, 4096);
        for (int i = 0; i < sample; i++) {
            int b = bytes[i] & 0xff;
            if (b == 0x09 || b == 0x0a || b == 0x0d) continue;
            if (b < 0x20) return true;
            if (b == 0x7f) return true;
        }
        return false;
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT WS editor: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
