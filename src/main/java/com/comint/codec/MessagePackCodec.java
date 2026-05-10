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
            String pretty = jsonMapper.writeValueAsString(value);
            // Audit fix: msgpack distinguishes int/uint sizes, ext, timestamp etc.
            // The Jackson Object mapping collapses these to plain Java types — so a
            // re-encode may produce a different wire-format than the original. Warn
            // the user so they don't get silent fidelity loss when sending edits.
            try {
                byte[] reEncoded = msgpackMapper.writeValueAsBytes(value);
                if (!bytesEqual(reEncoded, data)) {
                    return "/* COMINT MessagePack: lossy decode — wire format uses ext/timestamp/sized integers; re-encoded bytes will not match the original. */\n"
                            + pretty;
                }
            } catch (Throwable ignored) {}
            return pretty;
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
        // Strip a leading lossy-decode warning comment so the user can edit the JSON
        // beneath the warning and still encode successfully.
        String body = stripLeadingComment(trimmed);
        try {
            Object value = jsonMapper.readValue(body, Object.class);
            byte[] out = msgpackMapper.writeValueAsBytes(value);
            // Audit fix: enforce 32MB cap on encode output too — a maliciously crafted
            // JSON could blow up to a multi-gigabyte msgpack blob otherwise.
            if (out != null && out.length > MAX_PAYLOAD_BYTES) {
                throw new RuntimeException("MessagePack encode: result exceeds 32MB cap");
            }
            return out;
        } catch (Exception e) {
            throw new RuntimeException("MessagePack encode failed: " + (e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()), e);
        }
    }

    private static String stripLeadingComment(String s) {
        if (s == null) return "";
        String t = s.trim();
        if (!t.startsWith("/*")) return s;
        int end = t.indexOf("*/");
        if (end < 0) return s;
        return t.substring(end + 2).trim();
    }

    private static boolean bytesEqual(byte[] a, byte[] b) {
        if (a == b) return true;
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) {
            if (a[i] != b[i]) return false;
        }
        return true;
    }
}
