package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;

import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class ComintResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;
    private final RawEditor rawEditor;
    private final JPanel uiPanel;

    private HttpRequestResponse currentRequestResponse;
    private ProtocolCodec activeCodec;

    public ComintResponseEditor(MontoyaApi api, CodecRegistry codecRegistry, EditorCreationContext creationContext) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.rawEditor = creationContext != null && creationContext.editorMode() == EditorMode.READ_ONLY
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();

        this.uiPanel = new JPanel(new BorderLayout());
        uiPanel.add(rawEditor.uiComponent(), BorderLayout.CENTER);

        try {
            api.userInterface().applyThemeToComponent(uiPanel);
        } catch (Throwable ignored) {}
    }

    @Override
    public String caption() {
        return activeCodec != null
                ? "COMINT - " + activeCodec.name()
                : "COMINT";
    }

    @Override
    public Component uiComponent() {
        return uiPanel;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        try {
            if (requestResponse == null) return false;
            HttpResponse response;
            HttpRequest request;
            try {
                response = requestResponse.response();
                request = requestResponse.request();
            } catch (Throwable t) {
                return false;
            }
            if (response == null) return false;
            // WS-10: hide the COMINT response tab on the 101 Switching Protocols
            // half of a WebSocket upgrade — there's no body to decode.
            if (isWebSocketUpgrade(request, response)) return false;
            Optional<ProtocolCodec> codec = codecRegistry.codecForResponse(response, request);
            return codec.isPresent();
        } catch (Throwable t) {
            try {
                api.logging().logToError("isEnabledFor (response) error: " + safeMessage(t));
            } catch (Throwable ignored) {}
            return false;
        }
    }

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        this.currentRequestResponse = requestResponse;
        try {
            if (requestResponse == null) {
                this.activeCodec = null;
                rawEditor.setContents(ByteArray.byteArray(new byte[0]));
                return;
            }
            HttpResponse response = requestResponse.response();
            HttpRequest request = requestResponse.request();
            if (response == null) {
                this.activeCodec = null;
                rawEditor.setContents(ByteArray.byteArray(new byte[0]));
                return;
            }
            this.activeCodec = codecRegistry.codecForResponse(response, request).orElse(null);
            byte[] body = CodecUtil.safeBodyBytes(response);
            String decoded;
            if (activeCodec == null) {
                decoded = body.length == 0 ? "" : new String(body, StandardCharsets.UTF_8);
            } else {
                try {
                    String d = activeCodec.decode(body);
                    decoded = d == null ? "" : d;
                } catch (Throwable t) {
                    decoded = "/* COMINT decode error: " + safeMessage(t) + " */";
                }
            }
            byte[] decodedBytes = decoded.getBytes(StandardCharsets.UTF_8);
            byte[] full = HttpMessageFormatter.formatResponse(response, decodedBytes);
            rawEditor.setContents(ByteArray.byteArray(full));
        } catch (Throwable t) {
            try {
                api.logging().logToError("setRequestResponse (response) error: " + safeMessage(t));
            } catch (Throwable ignored) {}
            try {
                rawEditor.setContents(ByteArray.byteArray(("/* COMINT error: " + safeMessage(t) + " */").getBytes(StandardCharsets.UTF_8)));
            } catch (Throwable ignored) {}
        }
    }

    @Override
    public HttpResponse getResponse() {
        if (currentRequestResponse == null) return null;
        HttpResponse original;
        try {
            original = currentRequestResponse.response();
        } catch (Throwable t) {
            return null;
        }
        if (original == null) return null;
        if (!rawEditor.isModified()) {
            return original;
        }
        try {
            ByteArray contents = rawEditor.getContents();
            byte[] edited = contents == null ? new byte[0] : contents.getBytes();
            byte[] decodedBody = HttpMessageFormatter.extractBody(edited);
            byte[] reEncodedBody;
            if (activeCodec != null) {
                try {
                    String readable = decodedBody.length == 0 ? "" : new String(decodedBody, StandardCharsets.UTF_8);
                    byte[] originalBody = CodecUtil.safeBodyBytes(original);
                    reEncodedBody = activeCodec.encode(readable, originalBody);
                    if (reEncodedBody == null) reEncodedBody = new byte[0];
                } catch (Throwable t) {
                    api.logging().logToError("getResponse re-encode error: " + safeMessage(t));
                    reEncodedBody = decodedBody;
                }
            } else {
                reEncodedBody = decodedBody;
            }
            byte[] full = HttpMessageFormatter.reconstructWithEncodedBody(edited, reEncodedBody);
            try {
                return HttpResponse.httpResponse(ByteArray.byteArray(full));
            } catch (Throwable t) {
                api.logging().logToError("getResponse factory error: " + safeMessage(t));
                return original;
            }
        } catch (Throwable t) {
            try {
                api.logging().logToError("getResponse error: " + safeMessage(t));
            } catch (Throwable ignored) {}
            return original;
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

    @Override
    public Selection selectedData() {
        try {
            return rawEditor.selection().orElse(null);
        } catch (Throwable t) {
            return null;
        }
    }

    /** WS-10: detect the WebSocket upgrade pair — request has Upgrade: websocket
     *  (or Connection: Upgrade), or the response is 101 Switching Protocols. */
    private static boolean isWebSocketUpgrade(HttpRequest request, HttpResponse response) {
        try {
            if (response != null && response.statusCode() == 101) return true;
        } catch (Throwable ignored) {}
        if (request != null) {
            try {
                String upgrade = request.headerValue("Upgrade");
                if (upgrade != null && upgrade.toLowerCase(java.util.Locale.ROOT).contains("websocket")) {
                    return true;
                }
            } catch (Throwable ignored) {}
            try {
                String connection = request.headerValue("Connection");
                if (connection != null && connection.toLowerCase(java.util.Locale.ROOT).contains("upgrade")) {
                    return true;
                }
            } catch (Throwable ignored) {}
        }
        return false;
    }

    private static String safeMessage(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        if (m == null || m.isEmpty()) return t.getClass().getSimpleName();
        return m;
    }
}
