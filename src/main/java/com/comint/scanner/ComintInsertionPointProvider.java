package com.comint.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPointProvider;

import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Exposes each editable leaf field in a decoded protobuf / MessagePack / gRPC-Web
 * body as a Burp Scanner insertion point. Lets Burp's native scanner and any
 * third-party scanner extension fuzz binary-protocol fields without needing to
 * understand the wire format themselves.
 *
 * <p>GraphQL is excluded — its display form is the query text, not a JSON tree,
 * so JsonNode-pointer walking does not apply. (Burp's native JSON insertion
 * points already cover the {@code variables} object once it sees the wire body.)
 */
public class ComintInsertionPointProvider implements AuditInsertionPointProvider {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int MAX_INSERTION_POINTS = 256;
    /** Bound on JsonNode recursion depth — protects the Scanner thread from
     *  StackOverflowError on pathologically nested decoded payloads. */
    private static final int MAX_WALK_DEPTH = 256;

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;

    public ComintInsertionPointProvider(MontoyaApi api, CodecRegistry codecRegistry) {
        this.api = api;
        this.codecRegistry = codecRegistry;
    }

    @Override
    public List<AuditInsertionPoint> provideInsertionPoints(HttpRequestResponse baseHttpRequestResponse) {
        List<AuditInsertionPoint> result = new ArrayList<>();
        try {
            if (baseHttpRequestResponse == null) return result;
            HttpRequest req = baseHttpRequestResponse.request();
            if (req == null) return result;
            ProtocolCodec codec;
            try {
                codec = codecRegistry == null ? null
                        : codecRegistry.codecForRequest(req).orElse(null);
            } catch (Throwable t) { return result; }
            if (codec == null) return result;
            String name = codec.name();
            if ("GraphQL".equals(name)) return result;

            byte[] body = CodecUtil.safeBodyBytes(req);
            if (body.length == 0) return result;

            // R16: when the COMINT panel hands a request to "Do active scan", the body is
            // ALREADY in decoded JSON form (CT preserved as the original wire CT). When the
            // scanner is invoked from elsewhere (Burp's standard active-scan UI on a wire-
            // format request), the body is binary and needs decoding first.
            String decoded = null;
            JsonNode root = null;
            try {
                JsonNode maybeJson = MAPPER.readTree(body);
                if (maybeJson != null && (maybeJson.isObject() || maybeJson.isArray())) {
                    decoded = new String(body, java.nio.charset.StandardCharsets.UTF_8);
                    root = maybeJson;
                }
            } catch (Throwable ignored) {
                // Not JSON — fall through to wire-format decode.
            }
            if (root == null) {
                try { decoded = codec.decode(body); } catch (Throwable t) { return result; }
                if (decoded == null || decoded.isEmpty() || decoded.startsWith("/*")) return result;
                try { root = MAPPER.readTree(decoded); } catch (Throwable t) { return result; }
                if (root == null || root.isMissingNode()) return result;
            }

            boolean isProtobufShape = "Protobuf".equals(name) || "gRPC-Web".equals(name);
            List<String> pointers = new ArrayList<>();
            walkStringLeaves(root, "", pointers, isProtobufShape, 0);

            int added = 0;
            for (String ptr : pointers) {
                if (added >= MAX_INSERTION_POINTS) break;
                JsonNode leaf = root.at(ptr);
                String baseValue = leaf != null && leaf.isTextual() ? leaf.asText() : "";
                result.add(new ComintJsonInsertionPoint(
                        api, req, codec, decoded, ptr, baseValue, name));
                added++;
            }
        } catch (Throwable t) {
            try { api.logging().logToError("ComintInsertionPointProvider: " + safeMsg(t)); } catch (Throwable ignored) {}
        }
        return result;
    }

    static void walkStringLeaves(JsonNode node, String prefix, List<String> out, boolean protobufShape, int depth) {
        if (node == null) return;
        // Hard recursion bound — caller's MAX_INSERTION_POINTS still caps the leaf
        // count, but a deeply-nested JSON tree (e.g. {"a":{"a":{...}}}) can blow the
        // Scanner thread's stack before we hit the leaf cap. Bail at MAX_WALK_DEPTH.
        if (depth > MAX_WALK_DEPTH) return;
        if (node.isTextual()) {
            // Skip protobuf "type" tags — the type field itself is metadata, not user data.
            if (protobufShape && prefix.endsWith("/type")) return;
            out.add(prefix);
            return;
        }
        if (node.isObject()) {
            Iterator<Map.Entry<String, JsonNode>> it = node.fields();
            while (it.hasNext()) {
                Map.Entry<String, JsonNode> e = it.next();
                walkStringLeaves(e.getValue(), prefix + "/" + escapeJsonPointer(e.getKey()), out, protobufShape, depth + 1);
            }
        } else if (node.isArray()) {
            for (int i = 0; i < node.size(); i++) {
                walkStringLeaves(node.get(i), prefix + "/" + i, out, protobufShape, depth + 1);
            }
        }
    }

    /** Test-only helper retained at the previous arity to avoid breaking unit tests. */
    static void walkStringLeaves(JsonNode node, String prefix, List<String> out, boolean protobufShape) {
        walkStringLeaves(node, prefix, out, protobufShape, 0);
    }

    static String escapeJsonPointer(String s) {
        if (s == null) return "";
        return s.replace("~", "~0").replace("/", "~1");
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
