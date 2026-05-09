package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;

import com.comint.codec.CodecRegistry;

public class ComintRequestEditorProvider implements HttpRequestEditorProvider {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;

    public ComintRequestEditorProvider(MontoyaApi api, CodecRegistry codecRegistry) {
        this.api = api;
        this.codecRegistry = codecRegistry;
    }

    @Override
    public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext creationContext) {
        return new ComintRequestEditor(api, codecRegistry, creationContext);
    }
}
