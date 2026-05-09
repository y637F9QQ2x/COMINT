package com.comint.codec;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

public interface ProtocolCodec {

    String name();

    boolean isApplicableToRequest(HttpRequest request);

    boolean isApplicableToResponse(HttpResponse response, HttpRequest associatedRequest);

    String decode(byte[] data);

    byte[] encode(String readable);

    /**
     * Encode the user-edited form back to wire bytes, with access to the
     * original request body for context. Codecs that lose information when
     * displaying a stripped-down view (e.g. GraphQL — variables, operationName,
     * extensions are hidden in the editor) override this to merge the user's
     * edits back into the original envelope.
     *
     * <p>Default implementation simply delegates to {@link #encode(String)}.
     */
    default byte[] encode(String readable, byte[] originalBody) {
        return encode(readable);
    }
}

