package com.comint.scanner;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;

import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

/**
 * Insertion point that targets a single JSON-pointer path inside the COMINT
 * decoded body. Replacing the leaf with the scanner payload, re-encoding to
 * wire format, and returning the modified request lets Burp scan binary
 * protocols field-by-field.
 */
public class ComintJsonInsertionPoint implements AuditInsertionPoint {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Hard cap on the cached decoded JSON that gets re-parsed on every payload trial. */
    private static final int MAX_DECODED_JSON_BYTES = 32 * 1024 * 1024;

    private final MontoyaApi api;
    private final HttpRequest baseRequest;
    private final ProtocolCodec codec;
    private final String decodedJson;
    private final String pointer;
    private final String baseValue;
    private final String codecName;

    public ComintJsonInsertionPoint(MontoyaApi api,
                                    HttpRequest baseRequest,
                                    ProtocolCodec codec,
                                    String decodedJson,
                                    String pointer,
                                    String baseValue,
                                    String codecName) {
        this.api = api;
        this.baseRequest = baseRequest;
        this.codec = codec;
        this.decodedJson = decodedJson;
        this.pointer = pointer == null ? "" : pointer;
        this.baseValue = baseValue == null ? "" : baseValue;
        this.codecName = codecName == null ? "COMINT" : codecName;
    }

    @Override
    public String name() {
        return "COMINT " + codecName + " " + (pointer.isEmpty() ? "/" : pointer);
    }

    @Override
    public String baseValue() {
        return baseValue;
    }

    @Override
    public HttpRequest buildHttpRequestWithPayload(ByteArray payload) {
        if (baseRequest == null) return null;
        try {
            // Defensive cap: re-parsing a 100MB JSON for every scanner payload trial
            // would burn memory and time. Skip oversized bodies — Scanner sees
            // an unmodified base request for this position.
            if (decodedJson != null && decodedJson.length() > MAX_DECODED_JSON_BYTES) {
                logErr("decodedJson too large (" + decodedJson.length() + " chars) — skipping payload trial at " + pointer);
                return baseRequest;
            }
            String payloadStr = payload == null ? "" : payload.toString();
            JsonNode root = MAPPER.readTree(decodedJson);
            if (root == null) return baseRequest;
            replaceAtPointer(root, pointer, payloadStr);
            String mutated = MAPPER.writeValueAsString(root);
            byte[] originalBody = CodecUtil.safeBodyBytes(baseRequest);
            byte[] wire;
            try {
                wire = codec.encode(mutated, originalBody);
            } catch (Throwable t) {
                // Encoding failed (e.g. payload doesn't fit the wire-type at this position).
                // Return the unmodified base request so Scanner skips this trial.
                logErr("encode failed for " + pointer + ": " + safeMsg(t));
                return baseRequest;
            }
            if (wire == null) return baseRequest;
            return baseRequest.withBody(ByteArray.byteArray(wire));
        } catch (Throwable t) {
            logErr("buildHttpRequestWithPayload " + pointer + ": " + safeMsg(t));
            return baseRequest;
        }
    }

    @Override
    public List<Range> issueHighlights(ByteArray payload) {
        // Payload doesn't appear literally in the wire bytes (re-encoded), so
        // there's nothing useful to highlight in the UI.
        return Collections.emptyList();
    }

    static void replaceAtPointer(JsonNode root, String pointer, String newValue) {
        if (root == null || pointer == null || pointer.isEmpty()) return;
        // Split the pointer into tokens.
        String[] parts = pointer.split("/", -1);
        if (parts.length == 0) return;
        JsonNode current = root;
        // parts[0] is empty because pointer starts with "/".
        for (int i = 1; i < parts.length - 1; i++) {
            current = stepInto(current, unescapeJsonPointer(parts[i]));
            if (current == null || current.isMissingNode()) return;
        }
        String lastKey = unescapeJsonPointer(parts[parts.length - 1]);
        if (current.isObject()) {
            ((ObjectNode) current).set(lastKey, TextNode.valueOf(newValue));
        } else if (current.isArray()) {
            int idx;
            try { idx = Integer.parseInt(lastKey); } catch (NumberFormatException nfe) { return; }
            if (idx < 0 || idx >= current.size()) return;
            ((ArrayNode) current).set(idx, TextNode.valueOf(newValue));
        }
    }

    private static JsonNode stepInto(JsonNode node, String key) {
        if (node == null) return null;
        if (node.isObject()) return node.get(key);
        if (node.isArray()) {
            try {
                int idx = Integer.parseInt(key);
                if (idx < 0 || idx >= node.size()) return null;
                return node.get(idx);
            } catch (NumberFormatException nfe) {
                return null;
            }
        }
        return null;
    }

    private static String unescapeJsonPointer(String s) {
        if (s == null || s.isEmpty()) return "";
        return s.replace("~1", "/").replace("~0", "~");
    }

    private void logErr(String msg) {
        try { api.logging().logToError("ComintJsonInsertionPoint: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }

    @SuppressWarnings("unused")
    private static byte[] toBytes(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }
}
