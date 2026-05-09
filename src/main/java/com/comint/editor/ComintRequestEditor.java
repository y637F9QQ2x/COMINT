package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;

import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;

import javax.swing.JPanel;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

public class ComintRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;
    private final RawEditor rawEditor;
    private final JPanel uiPanel;

    private HttpRequestResponse currentRequestResponse;
    private ProtocolCodec activeCodec;

    public ComintRequestEditor(MontoyaApi api, CodecRegistry codecRegistry, EditorCreationContext creationContext) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.rawEditor = creationContext != null && creationContext.editorMode() == EditorMode.READ_ONLY
                ? api.userInterface().createRawEditor(EditorOptions.READ_ONLY)
                : api.userInterface().createRawEditor();

        // Wrap the RawEditor in a panel so applyThemeToComponent has a stable target.
        // RawEditor does not support syntax highlighting (Montoya API limitation, R9) —
        // applyThemeToComponent at least matches Burp's font/spacing.
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
            HttpRequest request;
            try {
                request = requestResponse.request();
            } catch (Throwable t) {
                return false;
            }
            if (request == null) return false;
            Optional<ProtocolCodec> codec = codecRegistry.codecForRequest(request);
            return codec.isPresent();
        } catch (Throwable t) {
            try {
                api.logging().logToError("isEnabledFor (request) error: " + safeMessage(t));
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
            HttpRequest request = requestResponse.request();
            if (request == null) {
                this.activeCodec = null;
                rawEditor.setContents(ByteArray.byteArray(new byte[0]));
                return;
            }
            this.activeCodec = codecRegistry.codecForRequest(request).orElse(null);
            byte[] body = CodecUtil.safeBodyBytes(request);
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
            byte[] full = HttpMessageFormatter.formatRequest(request, decodedBytes);
            rawEditor.setContents(ByteArray.byteArray(full));
        } catch (Throwable t) {
            try {
                api.logging().logToError("setRequestResponse (request) error: " + safeMessage(t));
            } catch (Throwable ignored) {}
            try {
                rawEditor.setContents(ByteArray.byteArray(("/* COMINT error: " + safeMessage(t) + " */").getBytes(StandardCharsets.UTF_8)));
            } catch (Throwable ignored) {}
        }
    }

    @Override
    public HttpRequest getRequest() {
        if (currentRequestResponse == null) return null;
        HttpRequest original;
        try {
            original = currentRequestResponse.request();
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
                    api.logging().logToError("getRequest re-encode error: " + safeMessage(t));
                    // Pass through the user's body verbatim if re-encode fails — better than dropping their edits.
                    reEncodedBody = decodedBody;
                }
            } else {
                reEncodedBody = decodedBody;
            }
            byte[] full = HttpMessageFormatter.reconstructWithEncodedBody(edited, reEncodedBody);
            HttpService service = original.httpService();
            try {
                if (service != null) {
                    return HttpRequest.httpRequest(service, ByteArray.byteArray(full));
                }
                return HttpRequest.httpRequest(ByteArray.byteArray(full));
            } catch (Throwable t) {
                api.logging().logToError("getRequest factory error: " + safeMessage(t));
                return original;
            }
        } catch (Throwable t) {
            try {
                api.logging().logToError("getRequest error: " + safeMessage(t));
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

    private static String safeMessage(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        if (m == null || m.isEmpty()) return t.getClass().getSimpleName();
        return m;
    }
}
