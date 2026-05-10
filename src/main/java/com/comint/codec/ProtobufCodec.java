package com.comint.codec;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;

public class ProtobufCodec implements ProtocolCodec {

    private static final String[] CONTENT_TYPES = {
            "application/x-protobuf",
            "application/protobuf",
            "application/vnd.google.protobuf"
    };

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
    private static final int MAX_RECURSION = 32;

    // Shared, thread-safe (Jackson docs: ObjectMapper is thread-safe after configuration).
    private static final ObjectMapper NODE_MAPPER = new ObjectMapper();

    private final ObjectMapper jsonMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public String name() {
        return "Protobuf";
    }

    @Override
    public boolean isApplicableToRequest(HttpRequest request) {
        String ct = CodecUtil.safeContentType(request);
        return matches(ct);
    }

    @Override
    public boolean isApplicableToResponse(HttpResponse response, HttpRequest associatedRequest) {
        return matches(CodecUtil.safeContentType(response));
    }

    private static boolean matches(String contentType) {
        if (contentType == null || contentType.isEmpty()) return false;
        // Do NOT claim grpc / grpc-web here — those are handled by GrpcWebCodec.
        if (CodecUtil.contentTypeContains(contentType, "grpc")) return false;
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
            return "/* COMINT Protobuf: payload too large (" + data.length + " bytes) */";
        }
        try {
            UnknownFieldSet ufs = UnknownFieldSet.parseFrom(data);
            ObjectNode out = ufsToJson(ufs, 0);
            return jsonMapper.writeValueAsString(out);
        } catch (Throwable t) {
            return "/* COMINT Protobuf decode error: " + safeMsg(t) + " */";
        }
    }

    @Override
    public byte[] encode(String readable) {
        if (readable == null) return new byte[0];
        String trimmed = readable.trim();
        if (trimmed.isEmpty() || trimmed.equals("{}")) {
            return new byte[0];
        }
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("Protobuf encode: refusing to encode error placeholder");
        }
        try {
            JsonNode root = jsonMapper.readTree(trimmed);
            if (root == null || !root.isObject()) {
                throw new RuntimeException("Protobuf encode: top-level must be a JSON object");
            }
            UnknownFieldSet ufs = jsonToUfs((ObjectNode) root, 0);
            byte[] out = ufs.toByteArray();
            // Audit fix: enforce the 32MB cap on encode output too.
            if (out != null && out.length > MAX_PAYLOAD_BYTES) {
                throw new RuntimeException("Protobuf encode: result exceeds 32MB cap");
            }
            return out;
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("Protobuf encode failed: " + safeMsg(t), t);
        }
    }

    static ObjectNode ufsToJson(UnknownFieldSet ufs, int depth) {
        ObjectMapper m = NODE_MAPPER;
        ObjectNode out = m.createObjectNode();
        if (ufs == null) return out;
        // Sort by field number for deterministic output.
        Map<Integer, UnknownFieldSet.Field> sorted = new TreeMap<>(ufs.asMap());
        for (Map.Entry<Integer, UnknownFieldSet.Field> e : sorted.entrySet()) {
            int fieldNumber = e.getKey();
            UnknownFieldSet.Field field = e.getValue();
            ArrayNode values = m.createArrayNode();

            for (long v : field.getVarintList()) {
                ObjectNode entry = m.createObjectNode();
                entry.put("type", "varint");
                entry.put("value", v);
                values.add(entry);
            }
            for (int v : field.getFixed32List()) {
                ObjectNode entry = m.createObjectNode();
                entry.put("type", "fixed32");
                entry.put("value", Integer.toUnsignedLong(v));
                values.add(entry);
            }
            for (long v : field.getFixed64List()) {
                ObjectNode entry = m.createObjectNode();
                entry.put("type", "fixed64");
                entry.put("value", v);
                values.add(entry);
            }
            for (ByteString bs : field.getLengthDelimitedList()) {
                values.add(decodeLengthDelimited(bs, depth, m));
            }
            // Groups (wire type 3/4) — deprecated; serialize as nested message under "group".
            for (UnknownFieldSet group : field.getGroupList()) {
                ObjectNode entry = m.createObjectNode();
                entry.put("type", "group");
                if (depth + 1 < MAX_RECURSION) {
                    entry.set("value", ufsToJson(group, depth + 1));
                } else {
                    entry.put("value", "/* depth limit */");
                }
                values.add(entry);
            }
            out.set(Integer.toString(fieldNumber), values);
        }
        return out;
    }

    private static ObjectNode decodeLengthDelimited(ByteString bs, int depth, ObjectMapper m) {
        ObjectNode entry = m.createObjectNode();
        if (bs == null) {
            entry.put("type", "bytes");
            entry.put("value", "");
            return entry;
        }
        byte[] raw = bs.toByteArray();
        // Try parse as nested message (only if depth allows and bytes non-empty).
        if (raw.length > 0 && depth + 1 < MAX_RECURSION) {
            try {
                UnknownFieldSet nested = UnknownFieldSet.parseFrom(raw);
                if (!nested.asMap().isEmpty() && reSerializesIdentically(nested, raw)) {
                    entry.put("type", "message");
                    entry.set("value", ufsToJson(nested, depth + 1));
                    return entry;
                }
            } catch (Throwable ignored) {
                // not a message
            }
        }
        // Try UTF-8 string heuristic.
        if (looksLikePrintableUtf8(raw)) {
            entry.put("type", "string");
            entry.put("value", new String(raw, StandardCharsets.UTF_8));
            return entry;
        }
        // Fallback: base64 bytes.
        entry.put("type", "bytes");
        entry.put("value", Base64.getEncoder().encodeToString(raw));
        return entry;
    }

    private static boolean reSerializesIdentically(UnknownFieldSet ufs, byte[] original) {
        try {
            byte[] reSerialized = ufs.toByteArray();
            // Length match is a strong signal — protobuf nested messages typically round-trip
            // exactly when the data is genuinely a nested message.
            if (reSerialized.length != original.length) return false;
            for (int i = 0; i < original.length; i++) {
                if (reSerialized[i] != original[i]) return false;
            }
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private static boolean looksLikePrintableUtf8(byte[] raw) {
        if (raw == null || raw.length == 0) return false;
        try {
            String s = new String(raw, StandardCharsets.UTF_8);
            // Reject if encoding back yields different bytes (invalid UTF-8 → replacement chars).
            byte[] back = s.getBytes(StandardCharsets.UTF_8);
            if (back.length != raw.length) return false;
            for (int i = 0; i < raw.length; i++) {
                if (back[i] != raw[i]) return false;
            }
            // Require mostly printable characters.
            int printable = 0;
            int total = s.length();
            if (total == 0) return false;
            for (int i = 0; i < total; i++) {
                char c = s.charAt(i);
                if (c == '\t' || c == '\n' || c == '\r') {
                    printable++;
                } else if (c >= 0x20 && c != 0x7f) {
                    printable++;
                }
            }
            // 95% printable threshold.
            return printable * 100 >= total * 95;
        } catch (Throwable t) {
            return false;
        }
    }

    static UnknownFieldSet jsonToUfs(ObjectNode obj, int depth) {
        if (depth >= MAX_RECURSION) {
            throw new RuntimeException("Protobuf encode: nesting depth exceeded");
        }
        UnknownFieldSet.Builder b = UnknownFieldSet.newBuilder();
        Iterator<Map.Entry<String, JsonNode>> it = obj.fields();
        while (it.hasNext()) {
            Map.Entry<String, JsonNode> e = it.next();
            String key = e.getKey();
            int fieldNumber;
            try {
                fieldNumber = Integer.parseInt(key);
            } catch (NumberFormatException nfe) {
                throw new RuntimeException("Protobuf encode: field key not an integer: " + key);
            }
            if (fieldNumber <= 0) {
                throw new RuntimeException("Protobuf encode: invalid field number " + fieldNumber);
            }
            JsonNode arr = e.getValue();
            if (arr == null || !arr.isArray()) {
                throw new RuntimeException("Protobuf encode: field " + key + " must map to an array");
            }
            UnknownFieldSet.Field.Builder fb = UnknownFieldSet.Field.newBuilder();
            for (JsonNode item : arr) {
                if (item == null || !item.isObject()) {
                    throw new RuntimeException("Protobuf encode: field " + key + " item must be an object");
                }
                ObjectNode entry = (ObjectNode) item;
                JsonNode typeNode = entry.get("type");
                JsonNode valueNode = entry.get("value");
                if (typeNode == null || !typeNode.isTextual()) {
                    throw new RuntimeException("Protobuf encode: field " + key + " missing 'type'");
                }
                String type = typeNode.asText();
                switch (type) {
                    case "varint":
                        fb.addVarint(valueAsLong(valueNode, key));
                        break;
                    case "fixed32": {
                        // Audit fix: range-check before narrowing — a fixed32 field can hold any
                        // 0..0xFFFFFFFF unsigned value. Cast-truncation silently produced wrong
                        // wire bytes when the user supplied something outside int range.
                        long v = valueAsLong(valueNode, key);
                        if (v < (long) Integer.MIN_VALUE || v > 0xFFFFFFFFL) {
                            throw new RuntimeException("Protobuf encode: fixed32 field " + key + " value out of range");
                        }
                        fb.addFixed32((int) v);
                        break;
                    }
                    case "fixed64":
                        fb.addFixed64(valueAsLong(valueNode, key));
                        break;
                    case "string":
                        if (valueNode == null || !valueNode.isTextual()) {
                            throw new RuntimeException("Protobuf encode: string field " + key + " value not text");
                        }
                        fb.addLengthDelimited(ByteString.copyFromUtf8(valueNode.asText()));
                        break;
                    case "bytes":
                        if (valueNode == null || !valueNode.isTextual()) {
                            throw new RuntimeException("Protobuf encode: bytes field " + key + " value not text");
                        }
                        try {
                            byte[] decoded = Base64.getDecoder().decode(valueNode.asText());
                            fb.addLengthDelimited(ByteString.copyFrom(decoded));
                        } catch (IllegalArgumentException ex) {
                            throw new RuntimeException("Protobuf encode: bytes field " + key + " invalid base64");
                        }
                        break;
                    case "message":
                        if (valueNode == null || !valueNode.isObject()) {
                            throw new RuntimeException("Protobuf encode: message field " + key + " value not object");
                        }
                        UnknownFieldSet nested = jsonToUfs((ObjectNode) valueNode, depth + 1);
                        fb.addLengthDelimited(nested.toByteString());
                        break;
                    case "group":
                        if (valueNode == null || !valueNode.isObject()) {
                            throw new RuntimeException("Protobuf encode: group field " + key + " value not object");
                        }
                        fb.addGroup(jsonToUfs((ObjectNode) valueNode, depth + 1));
                        break;
                    default:
                        throw new RuntimeException("Protobuf encode: unknown type '" + type + "' for field " + key);
                }
            }
            b.addField(fieldNumber, fb.build());
        }
        return b.build();
    }

    private static long valueAsLong(JsonNode v, String key) {
        if (v == null || v.isNull()) {
            throw new RuntimeException("Protobuf encode: field " + key + " value missing");
        }
        if (v.isNumber()) {
            // Audit fix: protobuf varint/fixed64 fields can carry uint64 values up to
            // 2^64-1 which don't fit in a signed long. Jackson's asLong() silently
            // truncates BigIntegers and large doubles. Reject out-of-range numbers
            // rather than emit wrong wire bytes; user can re-encode as a string.
            if (v.canConvertToLong()) {
                return v.asLong();
            }
            throw new RuntimeException("Protobuf encode: field " + key
                    + " numeric value does not fit in 64-bit signed long; supply as string for uint64");
        }
        if (v.isTextual()) {
            String text = v.asText();
            try {
                return Long.parseLong(text);
            } catch (NumberFormatException nfe) {
                // Audit fix: try uint64 parsing too — Long.parseUnsignedLong handles
                // values up to 2^64-1 by reinterpreting the result's bit pattern as
                // unsigned, which is the same wire-format encoding protobuf uses for
                // varint/fixed64 unsigned fields.
                try {
                    return Long.parseUnsignedLong(text);
                } catch (NumberFormatException nfe2) {
                    throw new RuntimeException("Protobuf encode: field " + key + " value not numeric: " + text);
                }
            }
        }
        throw new RuntimeException("Protobuf encode: field " + key + " value not numeric");
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
