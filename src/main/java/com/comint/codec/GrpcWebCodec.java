package com.comint.codec;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.google.protobuf.UnknownFieldSet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class GrpcWebCodec implements ProtocolCodec {

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
    private static final int MAX_FRAMES = 4096;
    private static final int FRAME_HEADER_BYTES = 5;

    private final ObjectMapper jsonMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Override
    public String name() {
        return "gRPC-Web";
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
        if (CodecUtil.contentTypeContains(contentType, "graphql")) return false;
        return CodecUtil.contentTypeContains(contentType, "application/grpc-web")
                || CodecUtil.contentTypeContains(contentType, "application/grpc+proto")
                || CodecUtil.contentTypeContains(contentType, "application/grpc");
    }

    @Override
    public String decode(byte[] data) {
        if (data == null || data.length == 0) {
            return emptyEnvelope(false);
        }
        if (data.length > MAX_PAYLOAD_BYTES) {
            return "/* COMINT gRPC-Web: payload too large (" + data.length + " bytes) */";
        }
        try {
            boolean textEncoded = false;
            byte[] frameBytes = data;
            // Stronger base64 detection: bytes must be in the base64 alphabet AND
            // the decoded bytes must start with a valid frame header.
            if (looksLikeBase64Text(data)) {
                String s = new String(data, StandardCharsets.US_ASCII).trim();
                if (s.isEmpty()) return emptyEnvelope(true);
                try {
                    byte[] decoded = Base64.getMimeDecoder().decode(s);
                    if (looksLikeFrameStream(decoded)) {
                        textEncoded = true;
                        frameBytes = decoded;
                    }
                } catch (IllegalArgumentException e) {
                    // Not actually base64 — keep raw treatment.
                }
            }
            return decodeFrames(frameBytes, textEncoded);
        } catch (Throwable t) {
            return "/* COMINT gRPC-Web decode error: " + safeMsg(t) + " */";
        }
    }

    /** Returns true if the bytes look like a valid gRPC-Web frame stream (non-strict — first frame fits). */
    static boolean looksLikeFrameStream(byte[] data) {
        if (data == null || data.length < FRAME_HEADER_BYTES) return false;
        int flag = data[0] & 0xff;
        if (flag != 0x00 && flag != 0x80) return false;
        long length = ((long) (data[1] & 0xff) << 24)
                | ((long) (data[2] & 0xff) << 16)
                | ((long) (data[3] & 0xff) << 8)
                | ((long) (data[4] & 0xff));
        if (length < 0 || length > Integer.MAX_VALUE - FRAME_HEADER_BYTES) return false;
        return (long) FRAME_HEADER_BYTES + length <= data.length;
    }

    private String decodeFrames(byte[] frameBytes, boolean textEncoded) {
        try {
            ObjectNode out = jsonMapper.createObjectNode();
            out.put("textEncoded", textEncoded);
            ArrayNode frames = jsonMapper.createArrayNode();

            int offset = 0;
            int frameCount = 0;
            while (offset < frameBytes.length) {
                if (frameCount >= MAX_FRAMES) {
                    out.put("truncated", true);
                    break;
                }
                if (frameBytes.length - offset < FRAME_HEADER_BYTES) {
                    ObjectNode tail = jsonMapper.createObjectNode();
                    tail.put("type", "trailing_garbage");
                    tail.put("bytes_b64", Base64.getEncoder().encodeToString(
                            slice(frameBytes, offset, frameBytes.length)));
                    frames.add(tail);
                    break;
                }
                int flag = frameBytes[offset] & 0xff;
                long length = ((long) (frameBytes[offset + 1] & 0xff) << 24)
                        | ((long) (frameBytes[offset + 2] & 0xff) << 16)
                        | ((long) (frameBytes[offset + 3] & 0xff) << 8)
                        | ((long) (frameBytes[offset + 4] & 0xff));
                offset += FRAME_HEADER_BYTES;
                if (length < 0 || length > Integer.MAX_VALUE - FRAME_HEADER_BYTES
                        || (long) offset + length > frameBytes.length) {
                    ObjectNode bad = jsonMapper.createObjectNode();
                    bad.put("type", "truncated_frame");
                    bad.put("flag", flag);
                    bad.put("declared_length", length);
                    bad.put("available_bytes", frameBytes.length - offset);
                    if (frameBytes.length - offset > 0) {
                        bad.put("payload_b64", Base64.getEncoder().encodeToString(
                                slice(frameBytes, offset, frameBytes.length)));
                    }
                    frames.add(bad);
                    break;
                }
                byte[] payload = slice(frameBytes, offset, offset + (int) length);
                offset += (int) length;

                ObjectNode frame = jsonMapper.createObjectNode();
                frame.put("flag", flag);
                if ((flag & 0x80) != 0) {
                    frame.put("type", "trailers");
                    frame.put("value", new String(payload, StandardCharsets.US_ASCII));
                } else {
                    frame.put("type", "data");
                    if (payload.length == 0) {
                        frame.set("value", jsonMapper.createObjectNode());
                    } else {
                        try {
                            UnknownFieldSet ufs = UnknownFieldSet.parseFrom(payload);
                            frame.set("value", ProtobufCodec.ufsToJson(ufs, 0));
                        } catch (Throwable t) {
                            ObjectNode raw = jsonMapper.createObjectNode();
                            raw.put("error", "protobuf parse failed: " + safeMsg(t));
                            raw.put("bytes_b64", Base64.getEncoder().encodeToString(payload));
                            frame.set("value", raw);
                        }
                    }
                }
                frames.add(frame);
                frameCount++;
            }
            out.set("frames", frames);
            return jsonMapper.writeValueAsString(out);
        } catch (Throwable t) {
            return "/* COMINT gRPC-Web decode error: " + safeMsg(t) + " */";
        }
    }

    private String emptyEnvelope(boolean textEncoded) {
        ObjectNode out = jsonMapper.createObjectNode();
        out.put("textEncoded", textEncoded);
        out.set("frames", jsonMapper.createArrayNode());
        try {
            return jsonMapper.writeValueAsString(out);
        } catch (Throwable t) {
            return "{\"textEncoded\":" + textEncoded + ",\"frames\":[]}";
        }
    }

    @Override
    public byte[] encode(String readable) {
        if (readable == null) return new byte[0];
        String trimmed = readable.trim();
        if (trimmed.isEmpty()) return new byte[0];
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("gRPC-Web encode: refusing to encode error placeholder");
        }
        try {
            JsonNode root = jsonMapper.readTree(trimmed);
            if (root == null || !root.isObject()) {
                throw new RuntimeException("gRPC-Web encode: top-level must be an object");
            }
            JsonNode framesNode = root.get("frames");
            if (framesNode == null || !framesNode.isArray()) {
                throw new RuntimeException("gRPC-Web encode: missing 'frames' array");
            }
            boolean textEncoded = root.has("textEncoded") && root.get("textEncoded").asBoolean(false);

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int frameIndex = 0;
            for (JsonNode frameNode : framesNode) {
                if (frameNode == null || !frameNode.isObject()) {
                    throw new RuntimeException("gRPC-Web encode: frame[" + frameIndex + "] not an object");
                }
                JsonNode typeNode = frameNode.get("type");
                if (typeNode == null) {
                    throw new RuntimeException("gRPC-Web encode: frame[" + frameIndex + "] missing 'type'");
                }
                String type = typeNode.asText("");
                if ("trailing_garbage".equals(type) || "truncated_frame".equals(type)) {
                    // Skip diagnostic-only entries — these were not real frames.
                    frameIndex++;
                    continue;
                }
                int flag;
                JsonNode flagNode = frameNode.get("flag");
                if (flagNode != null && flagNode.isNumber()) {
                    flag = flagNode.asInt() & 0xff;
                } else if ("trailers".equals(type)) {
                    flag = 0x80;
                } else {
                    flag = 0x00;
                }
                byte[] payload;
                JsonNode valueNode = frameNode.get("value");
                if ("trailers".equals(type)) {
                    if (valueNode == null || !valueNode.isTextual()) {
                        throw new RuntimeException("gRPC-Web encode: trailers frame[" + frameIndex + "] missing text value");
                    }
                    payload = valueNode.asText().getBytes(StandardCharsets.US_ASCII);
                } else if ("data".equals(type)) {
                    if (valueNode == null) {
                        throw new RuntimeException("gRPC-Web encode: data frame[" + frameIndex + "] missing value");
                    }
                    if (valueNode.isObject() && valueNode.has("bytes_b64")) {
                        try {
                            payload = Base64.getDecoder().decode(valueNode.get("bytes_b64").asText(""));
                        } catch (IllegalArgumentException ex) {
                            throw new RuntimeException("gRPC-Web encode: data frame[" + frameIndex + "] invalid bytes_b64");
                        }
                    } else if (valueNode.isObject()) {
                        try {
                            UnknownFieldSet ufs = ProtobufCodec.jsonToUfs((ObjectNode) valueNode, 0);
                            payload = ufs.toByteArray();
                        } catch (RuntimeException re) {
                            throw new RuntimeException("gRPC-Web encode: frame[" + frameIndex + "] protobuf encode: " + re.getMessage());
                        }
                    } else {
                        throw new RuntimeException("gRPC-Web encode: data frame[" + frameIndex + "] value not object");
                    }
                } else {
                    throw new RuntimeException("gRPC-Web encode: frame[" + frameIndex + "] unknown type '" + type + "'");
                }
                if (payload == null) payload = new byte[0];
                baos.write(flag & 0xff);
                int len = payload.length;
                baos.write((len >>> 24) & 0xff);
                baos.write((len >>> 16) & 0xff);
                baos.write((len >>> 8) & 0xff);
                baos.write(len & 0xff);
                baos.write(payload, 0, len);
                frameIndex++;
            }
            byte[] frameBytes = baos.toByteArray();
            // Audit fix: a textEncoded request with zero frames previously
            // round-tripped to empty bytes (decoded as a *binary* empty envelope on
            // the next pass), losing the textEncoded flag. Emit a single zero-length
            // data frame so the base64 wrapper is still applied and the codec can
            // re-detect the text mode.
            if (frameBytes.length == 0 && textEncoded) {
                frameBytes = new byte[]{0, 0, 0, 0, 0};
            }
            // Audit fix: enforce the encode-side 32MB cap so a maliciously crafted
            // JSON cannot blow up to a huge frame blob.
            if (frameBytes.length > MAX_PAYLOAD_BYTES) {
                throw new RuntimeException("gRPC-Web encode: result exceeds 32MB cap");
            }
            if (textEncoded) {
                byte[] b64 = Base64.getEncoder().encode(frameBytes);
                if (b64.length > MAX_PAYLOAD_BYTES) {
                    throw new RuntimeException("gRPC-Web encode: base64 result exceeds 32MB cap");
                }
                return b64;
            }
            return frameBytes;
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("gRPC-Web encode failed: " + safeMsg(t), t);
        }
    }

    static boolean looksLikeBase64Text(byte[] data) {
        if (data == null || data.length < FRAME_HEADER_BYTES) return false;
        // Sample a prefix and confirm it contains only base64 alphabet characters
        // (A-Za-z0-9+/=) and whitespace. Whitespace is common in MIME-style base64.
        int sampleLen = Math.min(data.length, 256);
        boolean sawBase64Char = false;
        for (int i = 0; i < sampleLen; i++) {
            int b = data[i] & 0xff;
            if (b >= 'A' && b <= 'Z') { sawBase64Char = true; continue; }
            if (b >= 'a' && b <= 'z') { sawBase64Char = true; continue; }
            if (b >= '0' && b <= '9') { sawBase64Char = true; continue; }
            if (b == '+' || b == '/' || b == '=' || b == '-' || b == '_') { sawBase64Char = true; continue; }
            if (b == '\r' || b == '\n' || b == '\t' || b == ' ') continue;
            return false;
        }
        return sawBase64Char;
    }

    private static byte[] slice(byte[] src, int from, int to) {
        if (src == null) return new byte[0];
        if (from < 0) from = 0;
        if (to > src.length) to = src.length;
        if (from >= to) return new byte[0];
        byte[] out = new byte[to - from];
        System.arraycopy(src, from, out, 0, to - from);
        return out;
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
