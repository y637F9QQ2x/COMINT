package com.comint.editor;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import com.comint.codec.CodecRegistry;

public class ComintResponseEditorProvider implements HttpResponseEditorProvider {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;

    public ComintResponseEditorProvider(MontoyaApi api, CodecRegistry codecRegistry) {
        this.api = api;
        this.codecRegistry = codecRegistry;
    }

    @Override
    public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext creationContext) {
        return new ComintResponseEditor(api, codecRegistry, creationContext);
    }
}
