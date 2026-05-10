package com.comint.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolSource;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.comint.bridge.ComintWsBridge;
import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;
import com.comint.ui.ComintTrafficEntry;
import com.comint.ui.ComintTrafficListener;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Captures HTTP request/response pairs and forwards them to the COMINT Traffic
 * panel. Pass-through handler — never modifies messages.
 */
public class ComintHttpHandler implements HttpHandler {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;
    private final ComintTrafficListener listener;
    private final AtomicInteger entryCounter;
    /** WS-10 fix: needed at request time to check the actual bridge port — the
     *  port is user-configurable so a captured snapshot would go stale. */
    private final ComintWsBridge wsBridge;
    private final ConcurrentMap<Integer, Long> requestStartTimes = new ConcurrentHashMap<>();
    /** R25: capture the originating Burp tool at request time so we can label the
     *  entry when the response comes back. Same eviction policy as requestStartTimes. */
    private final ConcurrentMap<Integer, String> requestSources = new ConcurrentHashMap<>();
    /** Hard cap on the pending-request map. Requests that never see a response would
     *  otherwise leak entries here forever; at the cap we evict the lowest message id
     *  to keep memory bounded during long sessions. */
    private static final int MAX_PENDING_REQUESTS = 4096;

    public ComintHttpHandler(MontoyaApi api,
                             CodecRegistry codecRegistry,
                             ComintTrafficListener listener,
                             AtomicInteger sharedCounter,
                             ComintWsBridge wsBridge) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.listener = listener;
        this.entryCounter = sharedCounter != null ? sharedCounter : new AtomicInteger();
        this.wsBridge = wsBridge;
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // R10 (FIX 4): the HttpHandler re-encodes ONLY when an outbound request
        // carries the X-COMINT-Original-Content-Type marker that COMINT itself sets
        // on the send-to-tool path (panel context menu / global context menu provider).
        // Untagged requests are pure passthrough — Burp's stored representation must
        // never be mutated for traffic the user didn't explicitly send through us.
        try {
            if (requestToBeSent != null) {
                if (requestStartTimes.size() >= MAX_PENDING_REQUESTS) {
                    // Drop the lowest message id (oldest) to bound memory during long sessions.
                    Integer oldest = null;
                    for (Integer k : requestStartTimes.keySet()) {
                        if (oldest == null || k < oldest) oldest = k;
                    }
                    if (oldest != null) {
                        requestStartTimes.remove(oldest);
                        requestSources.remove(oldest);
                    }
                }
                int msgId = requestToBeSent.messageId();
                requestStartTimes.put(msgId, System.currentTimeMillis());
                // R25: capture the originating tool — Proxy / Repeater / Intruder / etc.
                String src = sourceLabelFor(requestToBeSent.toolSource());
                if (src != null && !src.isEmpty()) requestSources.put(msgId, src);
            }
        } catch (Throwable t) {
            logErr("handleHttpRequestToBeSent: " + safeMsg(t));
        }
        try {
            HttpRequest reEncoded = maybeReEncodeForOriginalCt(requestToBeSent);
            if (reEncoded != null) {
                return RequestToBeSentAction.continueWith(reEncoded);
            }
        } catch (Throwable t) {
            // Re-encoding is best-effort — never block or crash the request.
            logErr("re-encode on send: " + safeMsg(t));
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    /** R10 (FIX 4): if the outbound request carries an
     *  {@code X-COMINT-Original-Content-Type} marker, re-encode the JSON body back
     *  to the original wire format using the matching codec, restore the original
     *  Content-Type, drop the marker, and return the rewritten request. Returns
     *  {@code null} when no rewrite is needed (untagged request, or any
     *  non-recoverable failure — caller falls through to passthrough). */
    private HttpRequest maybeReEncodeForOriginalCt(HttpRequest req) {
        if (req == null) return null;
        String origCt;
        try { origCt = req.headerValue("X-COMINT-Original-Content-Type"); }
        catch (Throwable t) { return null; }
        if (origCt == null || origCt.isEmpty()) return null;

        // R27: validate the marker against a whitelist of Content-Types we know
        // how to encode for. A scanner injecting `'; DROP TABLE ...` into the
        // header would otherwise reach the codec and either crash or emit
        // garbage — strip the marker and pass through unmodified instead.
        if (!isKnownOriginalContentType(origCt)) {
            try {
                return req.withRemovedHeader("X-COMINT-Original-Content-Type");
            } catch (Throwable t) {
                logErr("strip rejected X-COMINT-Original-Content-Type: " + safeMsg(t));
                return null;
            }
        }

        // Pick the codec by giving an existing codec lookup a probe request whose
        // Content-Type is the original — codecs match purely on Content-Type.
        ProtocolCodec codec;
        try {
            HttpRequest probe = req.withHeader("Content-Type", origCt);
            codec = codecRegistry == null ? null : codecRegistry.codecForRequest(probe).orElse(null);
        } catch (Throwable t) {
            return null;
        }

        // Read the JSON body the user (or COMINT) put in place of the wire bytes.
        byte[] jsonBody = CodecUtil.safeBodyBytes(req);
        String decoded = jsonBody.length == 0 ? "" : new String(jsonBody, java.nio.charset.StandardCharsets.UTF_8);

        // GraphQL never needs re-encoding — the wire format and tool format are both JSON.
        // For everything else, attempt the encode; on failure (user typed invalid JSON,
        // codec rejects payload, etc.) leave the body alone but still restore CT and
        // drop the marker so the request looks clean on the wire.
        byte[] wireBody = jsonBody;
        if (codec != null && !"GraphQL".equals(codec.name())) {
            try {
                byte[] encoded = codec.encode(decoded, jsonBody);
                if (encoded != null) wireBody = encoded;
            } catch (Throwable t) {
                logErr("codec.encode failed; sending JSON body unchanged: " + safeMsg(t));
            }
        }

        try {
            HttpRequest rewritten = req
                    .withRemovedHeader("X-COMINT-Original-Content-Type")
                    .withHeader("Content-Type", origCt)
                    .withBody(ByteArray.byteArray(wireBody));
            return rewritten;
        } catch (Throwable t) {
            logErr("rewrite outbound request failed: " + safeMsg(t));
            return null;
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            if (responseReceived == null) {
                return ResponseReceivedAction.continueWith(null);
            }
            int msgId = 0;
            try { msgId = responseReceived.messageId(); } catch (Throwable ignored) {}
            Long startTs = requestStartTimes.remove(msgId);
            long ts = startTs != null ? startTs : System.currentTimeMillis();
            // R25: prefer the source captured at request time; fall back to the response's
            // own toolSource() (Proxy responses arrive without a paired request callback in
            // some edge cases) and finally to the empty string.
            String source = requestSources.remove(msgId);
            if (source == null || source.isEmpty()) {
                try { source = sourceLabelFor(responseReceived.toolSource()); }
                catch (Throwable ignored) { source = ""; }
            }
            if (source == null) source = "";

            HttpRequest req = null;
            try { req = responseReceived.initiatingRequest(); } catch (Throwable ignored) {}

            String host = "";
            String url = "";
            String method = "";
            String protocol = "HTTP";
            if (req != null) {
                try {
                    burp.api.montoya.http.HttpService svc = req.httpService();
                    if (svc != null) {
                        host = svc.host() == null ? "" : svc.host();
                        if (svc.secure()) protocol = "HTTPS";
                    }
                } catch (Throwable ignored) {}
                try { url = req.url(); if (url == null) url = ""; } catch (Throwable ignored) {}
                method = CodecUtil.safeMethod(req);
                // WS-10: classify the WebSocket handshake first — it's an HTTP request
                // (so it reaches this handler) but it must show up as "WS", not as a
                // bridge or plain HTTP entry. Checking the handshake before the bridge
                // matters for the case where the test target itself is on 127.0.0.1.
                if (isWebSocketHandshake(req, responseReceived)) {
                    protocol = "WS";
                } else if (isBridgeRequest(host, req, bridgePortOrZero())) {
                    // WS-3: label requests targeting the embedded bridge so they show up
                    // in the Traffic tab as "WS-Bridge" rather than plain HTTP/HTTPS.
                    protocol = "WS-Bridge";
                }
            }

            String codecName = "None";
            if (req != null) {
                try {
                    Optional<ProtocolCodec> codec = codecRegistry.codecForResponse(responseReceived, req);
                    if (codec.isPresent()) codecName = codec.get().name();
                    else {
                        Optional<ProtocolCodec> reqCodec = codecRegistry.codecForRequest(req);
                        if (reqCodec.isPresent()) codecName = reqCodec.get().name();
                    }
                } catch (Throwable ignored) {}
            }

            int statusCode = 0;
            String reason = "";
            int length = 0;
            try { statusCode = responseReceived.statusCode(); } catch (Throwable ignored) {}
            try {
                String r = responseReceived.reasonPhrase();
                if (r != null) reason = r;
            } catch (Throwable ignored) {}
            try {
                if (responseReceived.body() != null) length = responseReceived.body().length();
            } catch (Throwable ignored) {}

            ComintTrafficEntry entry = ComintTrafficEntry.builder()
                    .id(entryCounter.incrementAndGet())
                    .timestamp(ts)
                    .kind(ComintTrafficEntry.Kind.HTTP)
                    .host(host)
                    .method(method)
                    .url(url)
                    .protocol(protocol)
                    .codec(codecName)
                    .statusCode(statusCode)
                    .reason(reason)
                    .length(length)
                    .httpRequest(req)
                    .httpResponse(responseReceived)
                    .source(source)
                    .build();

            if (listener != null) {
                try { listener.onEntry(entry); } catch (Throwable t) { logErr("listener.onEntry: " + safeMsg(t)); }
            }
        } catch (Throwable t) {
            logErr("handleHttpResponseReceived: " + safeMsg(t));
        }
        try {
            return ResponseReceivedAction.continueWith(responseReceived);
        } catch (Throwable t) {
            logErr("ResponseReceivedAction.continueWith: " + safeMsg(t));
            return ResponseReceivedAction.continueWith(responseReceived);
        }
    }

    /** R27: only re-encode when the marker header value matches a Content-Type
     *  COMINT actually targets. Returns true on a case-insensitive prefix match
     *  against any of the known wire-format media types. Anything else (a scanner
     *  payload, garbage, an unknown CT) gets passed through with the marker stripped. */
    private static boolean isKnownOriginalContentType(String ct) {
        if (ct == null) return false;
        String lower = ct.trim().toLowerCase(java.util.Locale.ROOT);
        if (lower.isEmpty()) return false;
        return lower.startsWith("application/x-protobuf")
                || lower.startsWith("application/protobuf")
                || lower.startsWith("application/vnd.msgpack")
                || lower.startsWith("application/x-msgpack")
                || lower.startsWith("application/msgpack")
                || lower.startsWith("application/grpc-web")
                || lower.startsWith("application/grpc")
                || lower.startsWith("application/json")
                || lower.startsWith("application/graphql");
    }

    /** R25: map a Burp ToolSource to the user-facing Source column label.
     *  Returns the empty string when the source is missing. */
    private static String sourceLabelFor(ToolSource ts) {
        if (ts == null) return "";
        ToolType type;
        try { type = ts.toolType(); } catch (Throwable t) { return ""; }
        if (type == null) return "";
        // Spec mapping for the headline tools; fall back to whatever Burp calls it
        // for the rest (Sequencer / Decoder / Logger / future tools).
        if (type == ToolType.PROXY) return "Proxy";
        if (type == ToolType.REPEATER) return "Repeater";
        if (type == ToolType.INTRUDER) return "Intruder";
        if (type == ToolType.SCANNER) return "Scanner";
        if (type == ToolType.EXTENSIONS) return "Extension";
        try {
            String name = type.toolName();
            return name == null ? "" : name;
        } catch (Throwable t) {
            return "";
        }
    }

    /** WS-10: detect a WebSocket handshake — the request carries Upgrade: websocket
     *  or the response is 101 Switching Protocols. Either signal alone is sufficient. */
    private static boolean isWebSocketHandshake(HttpRequest req, HttpResponseReceived resp) {
        try {
            if (resp != null && resp.statusCode() == 101) return true;
        } catch (Throwable ignored) {}
        try {
            if (req != null) {
                String upgrade = req.headerValue("Upgrade");
                if (upgrade != null && upgrade.toLowerCase(java.util.Locale.ROOT).contains("websocket")) {
                    return true;
                }
            }
        } catch (Throwable ignored) {}
        return false;
    }

    private int bridgePortOrZero() {
        try { return wsBridge != null ? wsBridge.port() : 0; }
        catch (Throwable t) { return 0; }
    }

    /** True when the request targets the embedded WS bridge endpoint on loopback.
     *  WS-10: must match the exact configured bridge port AND the exact "/ws" path
     *  (or "/ws?…") — otherwise a test target on 127.0.0.1 with a /ws/echo endpoint
     *  would be misclassified as bridge traffic and trigger the bridge layout. */
    private static boolean isBridgeRequest(String host, HttpRequest req, int bridgePort) {
        if (host == null || req == null || bridgePort <= 0) return false;
        if (!"127.0.0.1".equals(host) && !"localhost".equals(host)) return false;
        try {
            burp.api.montoya.http.HttpService svc = req.httpService();
            if (svc == null || svc.port() != bridgePort) return false;
        } catch (Throwable t) {
            return false;
        }
        try {
            String p = req.path();
            if (p == null) return false;
            return p.equals("/ws") || p.startsWith("/ws?");
        } catch (Throwable t) {
            return false;
        }
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT HTTP: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
