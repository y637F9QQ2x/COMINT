package com.comint.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.UnknownFieldSet;
import org.msgpack.jackson.dataformat.MessagePackFactory;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Pseudo-codec for WebSocket payloads. Not registered with CodecRegistry — the
 * regular {@link ProtocolCodec} contract assumes HTTP request/response context,
 * which WebSockets lack. Instead, this class is invoked directly by the
 * WebSocket message editor and handler to attempt decoding of common payload
 * formats (JSON, GraphQL-WS envelope, MessagePack, Protobuf).
 */
public final class WebSocketCodec {

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;

    private final ObjectMapper jsonMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
    private final ObjectMapper compactMapper = new ObjectMapper();
    private final ObjectMapper msgpackMapper = new ObjectMapper(new MessagePackFactory());
    private final GraphQLCodec graphQL = new GraphQLCodec();

    public String name() {
        return "WebSocket";
    }

    /**
     * Decode a text WebSocket payload. Returns a JSON envelope describing the
     * detected sub-protocol so encoding can reverse it.
     */
    public String decodeText(String payload) {
        if (payload == null) {
            return wrap("text_empty", "");
        }
        if (payload.length() > MAX_PAYLOAD_BYTES) {
            return "/* COMINT WebSocket: text payload too large (" + payload.length() + " chars) */";
        }
        try {
            String trimmed = payload.trim();
            if (trimmed.isEmpty()) {
                return wrap("text_empty", "");
            }
            char first = trimmed.charAt(0);
            if (first == '{' || first == '[') {
                JsonNode root;
                try {
                    root = jsonMapper.readTree(trimmed);
                } catch (Throwable t) {
                    return wrap("text", payload);
                }
                if (root == null) {
                    return wrap("text", payload);
                }
                // graphql-ws / subscriptions-transport-ws envelope detection
                if (root.isObject()) {
                    JsonNode type = root.get("type");
                    JsonNode pl = root.get("payload");
                    if (type != null && type.isTextual() && pl != null && pl.isObject()
                            && (pl.has("query") || hasPersistedQuery(pl))) {
                        ObjectNode out = jsonMapper.createObjectNode();
                        out.put("kind", "graphql_ws");
                        out.set("envelope", root.deepCopy());
                        // Pre-format inner payload via the GraphQL codec so the user sees pretty query/vars.
                        try {
                            byte[] inner = compactMapper.writeValueAsBytes(pl);
                            String prettyInner = graphQL.decode(inner);
                            out.put("payload_pretty", prettyInner);
                        } catch (Throwable ignored) {}
                        return write(out);
                    }
                }
                ObjectNode out = jsonMapper.createObjectNode();
                out.put("kind", "json");
                out.set("value", root);
                return write(out);
            }
            return wrap("text", payload);
        } catch (Throwable t) {
            return "/* COMINT WebSocket text decode error: " + safeMsg(t) + " */";
        }
    }

    /** Encode an edited text envelope back to a single string payload. */
    public String encodeText(String readable) {
        if (readable == null) return "";
        String trimmed = readable.trim();
        if (trimmed.isEmpty()) return "";
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("WebSocket encode: refusing to encode error placeholder");
        }
        try {
            JsonNode root = jsonMapper.readTree(trimmed);
            if (root == null || !root.isObject()) {
                // Not a recognized envelope — emit verbatim so users can free-form edit.
                return readable;
            }
            String kind = root.path("kind").asText("");
            if ("text".equals(kind) || "text_empty".equals(kind)) {
                JsonNode v = root.get("value");
                return (v != null && v.isTextual()) ? v.asText() : "";
            }
            if ("json".equals(kind)) {
                JsonNode v = root.get("value");
                if (v == null) return "";
                return compactMapper.writeValueAsString(v);
            }
            if ("graphql_ws".equals(kind)) {
                JsonNode envelope = root.get("envelope");
                if (envelope == null || !envelope.isObject()) {
                    throw new RuntimeException("WebSocket encode: graphql_ws envelope missing");
                }
                return compactMapper.writeValueAsString(envelope);
            }
            // Unknown kind — emit verbatim so users can hand-edit to whatever they need.
            return readable;
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("WebSocket text encode failed: " + safeMsg(t), t);
        }
    }

    /** Decode a binary WebSocket payload. Detection order: MessagePack → Protobuf → raw bytes. */
    public String decodeBinary(byte[] data) {
        if (data == null || data.length == 0) {
            return wrapBinary("binary_empty", "");
        }
        if (data.length > MAX_PAYLOAD_BYTES) {
            return "/* COMINT WebSocket: binary payload too large (" + data.length + " bytes) */";
        }
        try {
            // Try MessagePack first.
            try {
                Object value = msgpackMapper.readValue(data, Object.class);
                byte[] reSerialized = msgpackMapper.writeValueAsBytes(value);
                if (bytesEqual(reSerialized, data)) {
                    ObjectNode out = jsonMapper.createObjectNode();
                    out.put("kind", "msgpack");
                    out.set("value", jsonMapper.valueToTree(value));
                    return write(out);
                }
            } catch (Throwable ignored) {}

            // Try Protobuf (UnknownFieldSet).
            try {
                UnknownFieldSet ufs = UnknownFieldSet.parseFrom(data);
                if (!ufs.asMap().isEmpty() && ufs.toByteArray().length == data.length) {
                    ObjectNode out = jsonMapper.createObjectNode();
                    out.put("kind", "protobuf");
                    out.set("value", ProtobufCodec.ufsToJson(ufs, 0));
                    return write(out);
                }
            } catch (Throwable ignored) {}

            return wrapBinary("binary", Base64.getEncoder().encodeToString(data));
        } catch (Throwable t) {
            return "/* COMINT WebSocket binary decode error: " + safeMsg(t) + " */";
        }
    }

    /** Encode an edited binary envelope back to bytes. */
    public byte[] encodeBinary(String readable) {
        if (readable == null) return new byte[0];
        String trimmed = readable.trim();
        if (trimmed.isEmpty()) return new byte[0];
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("WebSocket encode: refusing to encode error placeholder");
        }
        try {
            JsonNode root = jsonMapper.readTree(trimmed);
            if (root == null || !root.isObject()) {
                throw new RuntimeException("WebSocket encode: binary envelope must be a JSON object");
            }
            String kind = root.path("kind").asText("");
            JsonNode v = root.get("value");
            if ("binary".equals(kind) || "binary_empty".equals(kind)) {
                if (v == null || !v.isTextual()) return new byte[0];
                String b64 = v.asText();
                if (b64.isEmpty()) return new byte[0];
                try {
                    return Base64.getDecoder().decode(b64);
                } catch (IllegalArgumentException ex) {
                    throw new RuntimeException("WebSocket encode: invalid base64");
                }
            }
            if ("msgpack".equals(kind)) {
                if (v == null) return new byte[0];
                Object obj = compactMapper.treeToValue(v, Object.class);
                return msgpackMapper.writeValueAsBytes(obj);
            }
            if ("protobuf".equals(kind)) {
                if (v == null || !v.isObject()) {
                    throw new RuntimeException("WebSocket encode: protobuf 'value' must be object");
                }
                UnknownFieldSet ufs = ProtobufCodec.jsonToUfs((ObjectNode) v, 0);
                return ufs.toByteArray();
            }
            throw new RuntimeException("WebSocket encode: unknown binary kind '" + kind + "'");
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("WebSocket binary encode failed: " + safeMsg(t), t);
        }
    }

    private boolean hasPersistedQuery(JsonNode obj) {
        if (obj == null) return false;
        JsonNode ext = obj.get("extensions");
        if (ext == null || !ext.isObject()) return false;
        JsonNode pq = ext.get("persistedQuery");
        return pq != null && pq.isObject();
    }

    private static boolean bytesEqual(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        for (int i = 0; i < a.length; i++) if (a[i] != b[i]) return false;
        return true;
    }

    private String wrap(String kind, String value) {
        ObjectNode out = jsonMapper.createObjectNode();
        out.put("kind", kind);
        out.put("value", value == null ? "" : value);
        return write(out);
    }

    private String wrapBinary(String kind, String b64) {
        ObjectNode out = jsonMapper.createObjectNode();
        out.put("kind", kind);
        out.put("value", b64 == null ? "" : b64);
        return write(out);
    }

    private String write(JsonNode node) {
        try {
            return jsonMapper.writeValueAsString(node);
        } catch (Throwable t) {
            return "{}";
        }
    }

    @SuppressWarnings("unused")
    private static byte[] toBytes(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
