package com.comint.codec;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.msgpack.jackson.dataformat.MessagePackFactory;

public class MessagePackCodec implements ProtocolCodec {

    private static final String[] CONTENT_TYPES = {
            "application/msgpack",
            "application/x-msgpack",
            "application/vnd.msgpack"
    };

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;

    private final ObjectMapper msgpackMapper = new ObjectMapper(new MessagePackFactory());
    private final ObjectMapper jsonMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public String name() {
        return "MessagePack";
    }

    @Override
    public boolean isApplicableToRequest(HttpRequest request) {
        return matches(CodecUtil.safeContentType(request));
    }

    @Override
    public boolean isApplicableToResponse(HttpResponse response, HttpRequest associatedRequest) {
        return matches(CodecUtil.safeContentType(response));
    }

    private static boolean matches(String contentType) {
        if (contentType == null || contentType.isEmpty()) return false;
        for (String t : CONTENT_TYPES) {
            if (CodecUtil.contentTypeContains(contentType, t)) return true;
        }
        return false;
    }

    @Override
    public String decode(byte[] data) {
        if (data == null || data.length == 0) {
            return "{}";
        }
        if (data.length > MAX_PAYLOAD_BYTES) {
            return "/* COMINT MessagePack: payload too large (" + data.length + " bytes) */";
        }
        try {
            Object value = msgpackMapper.readValue(data, Object.class);
            return jsonMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "/* COMINT MessagePack decode error: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()) + " */";
        }
    }

    @Override
    public byte[] encode(String readable) {
        if (readable == null || readable.isEmpty()) {
            return new byte[0];
        }
        String trimmed = readable.trim();
        if (trimmed.isEmpty()) {
            return new byte[0];
        }
        if (trimmed.startsWith("/*")) {
            // Decode error placeholder — refuse to encode rather than corrupt.
            throw new RuntimeException("MessagePack encode: refusing to encode error placeholder");
        }
        try {
            Object value = jsonMapper.readValue(trimmed, Object.class);
            return msgpackMapper.writeValueAsBytes(value);
        } catch (Exception e) {
            throw new RuntimeException("MessagePack encode failed: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()), e);
        }
    }
}
