package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedWebSocketMessageEditor;
import burp.api.montoya.ui.editor.extension.WebSocketMessageEditorProvider;

import com.comint.codec.WebSocketCodec;

public class ComintWebSocketMessageEditorProvider implements WebSocketMessageEditorProvider {

    private final MontoyaApi api;
    private final WebSocketCodec codec;

    public ComintWebSocketMessageEditorProvider(MontoyaApi api, WebSocketCodec codec) {
        this.api = api;
        this.codec = codec;
    }

    @Override
    public ExtensionProvidedWebSocketMessageEditor provideMessageEditor(EditorCreationContext creationContext) {
        return new ComintWebSocketMessageEditor(api, codec, creationContext);
    }
}
