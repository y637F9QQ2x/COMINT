package com.comint.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.comint.codec.CodecRegistry;
import com.comint.codec.ProtocolCodec;
import com.comint.ui.ComintTrafficEntry;
import com.comint.ui.ComintTrafficListener;

import fi.iki.elonen.NanoHTTPD;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * NanoHTTPD-based bridge handler. Burp's bundled JRE omits {@code jdk.httpserver},
 * so we use NanoHTTPD instead — relocated to {@code com.comint.shaded.nanohttpd}
 * by Shadow JAR so it can't collide with anything else on Burp's classpath.
 *
 * <p>Same contract as before:
 * <ul>
 *   <li>POST /ws — translates one HTTP request into one WebSocket round-trip.</li>
 *   <li>Loopback-only — server binds to 127.0.0.1 and the handler also rejects
 *       any non-loopback remote IP defensively.</li>
 *   <li>Body capped at 32 MB; rate limited to 100 req/s; per-connection inbox
 *       bounded by {@link PooledWsConnection}.</li>
 *   <li>Every callback path is wrapped in {@code try { ... } catch (Throwable)} —
 *       errors come back as JSON, never propagate to Burp's JVM.</li>
 * </ul>
 */
final class ComintWsBridgeHandler extends NanoHTTPD {

    static final String HEADER_TARGET    = "x-comint-ws-target";
    static final String HEADER_TIMEOUT   = "x-comint-ws-timeout";
    static final String HEADER_EXPECT    = "x-comint-ws-expect";
    static final String HEADER_BRIDGE    = "x-comint-bridge";
    static final String RESP_DIRECTION   = "X-COMINT-WS-Direction";

    private static final int MAX_REQUEST_BODY_BYTES = 32 * 1024 * 1024;
    private static final long DEFAULT_TIMEOUT_MS = 5_000L;
    private static final long MAX_TIMEOUT_MS     = 60_000L;
    private static final int HANDLER_THREADS = 16;
    /** Audit fix: aggregate in-flight request-body memory cap. The single-request
     *  cap (32 MB) doesn't bound HANDLER_THREADS × 32 MB = 512 MB transient peaks
     *  during burst. 128 MB total in-flight is a safe ceiling for an embedded
     *  bridge. Permits are bytes; we acquire equal-to-Content-Length and release
     *  in {@code finally}. */
    private static final int MAX_INFLIGHT_BYTES = 128 * 1024 * 1024;
    private static final java.util.concurrent.Semaphore inflightBytes =
            new java.util.concurrent.Semaphore(MAX_INFLIGHT_BYTES, true);

    private final MontoyaApi api;
    private final WsConnectionPool pool;
    private final BridgeRateLimiter limiter;
    private final FixedPoolRunner runner;
    /** Bug 1+2 fix — these let the bridge publish a traffic entry per request. */
    private final ComintTrafficListener trafficListener;
    private final AtomicInteger sharedCounter;
    private final CodecRegistry codecRegistry;
    private final int boundPort;

    ComintWsBridgeHandler(MontoyaApi api, String hostname, int port,
                          WsConnectionPool pool, BridgeRateLimiter limiter,
                          ComintTrafficListener trafficListener,
                          AtomicInteger sharedCounter,
                          CodecRegistry codecRegistry) {
        super(hostname, port);
        this.api = api;
        this.pool = pool;
        this.limiter = limiter;
        this.trafficListener = trafficListener;
        this.sharedCounter = sharedCounter != null ? sharedCounter : new AtomicInteger();
        this.codecRegistry = codecRegistry;
        this.boundPort = port;
        this.runner = new FixedPoolRunner();
        setAsyncRunner(runner);
    }

    @Override
    public void stop() {
        try { super.stop(); } catch (Throwable ignored) {}
        try { runner.shutdown(); } catch (Throwable ignored) {}
    }

    @Override
    public Response serve(IHTTPSession session) {
        if (session == null) return errorResp(new Outcome(), 500, "internal", "null session");
        Outcome out = new Outcome();
        Response result;
        try {
            result = serveInner(session, out);
        } catch (Throwable t) {
            logErr("serve: " + safeMsg(t));
            result = errorResp(out, 500, "internal", "internal bridge error");
        }
        // Bugs 1 + 2 fix — bridge requests don't pass through Burp's HttpHandler
        // because they go straight from the user's tool to NanoHTTPD inside the
        // extension. Synthesize an HttpRequest/HttpResponse pair from the bytes
        // we just handled and publish it to the COMINT Traffic listener so the
        // row both appears AND has a populated detail pane.
        try {
            publishTrafficEntry(session, out);
        } catch (Throwable t) {
            logErr("publishTrafficEntry: " + safeMsg(t));
        }
        return result;
    }

    /** Mutable per-request state so response builders can record what they returned
     *  AND so the publish step can synthesize the matching HttpRequest/HttpResponse. */
    static final class Outcome {
        byte[] requestBody = new byte[0];
        int statusCode = 200;
        String responseContentType = "application/json";
        byte[] responseBody = new byte[0];
        final LinkedHashMap<String, String> responseHeaders = new LinkedHashMap<>();
    }

    private Response serveInner(IHTTPSession session, Outcome out) {
        Map<String, String> headers = session.getHeaders(); // keys are lowercased by NanoHTTPD

        // Loop guard — bail fast if a request comes back into us recursively.
        if (headers.get(HEADER_BRIDGE) != null) {
            return errorResp(out, 508, "loop_detected", "X-COMINT-Bridge already set");
        }

        // Defence-in-depth on top of binding to 127.0.0.1.
        String remoteIp = session.getRemoteIpAddress();
        if (remoteIp != null && !isLoopbackIp(remoteIp)) {
            return errorResp(out, 403, "forbidden", "loopback only");
        }

        if (session.getMethod() != Method.POST) {
            return errorResp(out, 405, "method_not_allowed", "POST required");
        }

        if (!limiter.tryAcquire()) {
            return errorResp(out, 429, "rate_limited", "bridge throttle: 100 req/s");
        }

        String target = headers.get(HEADER_TARGET);
        if (target == null || target.isEmpty()
                || (!target.startsWith("ws://") && !target.startsWith("wss://"))) {
            return errorResp(out, 400, "invalid_target",
                    "X-COMINT-WS-Target must start with ws:// or wss://");
        }

        long timeoutMs = parseTimeout(headers.get(HEADER_TIMEOUT));
        boolean wantAll = "all".equalsIgnoreCase(headers.get(HEADER_EXPECT));
        boolean binaryFrame = isBinaryContent(headers.get("content-type"));

        // Read body — honour Content-Length manually because NanoHTTPD's
        // getInputStream() is the raw socket stream after headers and does not
        // EOF at content-length on its own.
        int contentLength;
        try {
            String cl = headers.get("content-length");
            contentLength = cl == null ? 0 : Integer.parseInt(cl.trim());
        } catch (NumberFormatException nfe) {
            return errorResp(out, 400, "invalid_content_length", "Content-Length is not a number");
        }
        if (contentLength < 0) return errorResp(out, 400, "invalid_content_length", "negative");
        if (contentLength > MAX_REQUEST_BODY_BYTES) {
            return errorResp(out, 413, "request_too_large", "request body exceeds 32MB cap");
        }
        // Audit fix: bound aggregate in-flight memory across all concurrent
        // requests. tryAcquire returns immediately so a burst is rejected with
        // 503 rather than allowed to expand to (HANDLER_THREADS × 32 MB).
        boolean reservedBytes = false;
        if (contentLength > 0) {
            if (!inflightBytes.tryAcquire(contentLength)) {
                return errorResp(out, 503, "in_flight_capacity",
                        "bridge in-flight memory cap reached; retry shortly");
            }
            reservedBytes = true;
        }
        byte[] body;
        try {
            body = new byte[contentLength];
            if (contentLength > 0) {
                InputStream in = session.getInputStream();
                int total = 0;
                while (total < contentLength) {
                    try {
                        int r = in.read(body, total, contentLength - total);
                        if (r < 0) {
                            // Audit fix: previously broke out and proceeded with a partially
                            // zero-padded body. That gets forwarded to the WS target as a
                            // truncated frame and stored as the synthesized request bytes —
                            // both wrong. Reject with 400 instead.
                            return errorResp(out, 400, "incomplete_body",
                                    "EOF after " + total + " of " + contentLength + " bytes");
                        }
                        total += r;
                    } catch (IOException ioe) {
                        return errorResp(out, 400, "read_failed", sanitizeMsg(safeMsg(ioe)));
                    }
                }
            }
        } finally {
            if (reservedBytes) inflightBytes.release(contentLength);
        }
        // Capture the request body so publishTrafficEntry can rebuild the synthetic
        // HttpRequest after serveInner returns.
        out.requestBody = body;

        // Acquire pooled connection.
        PooledWsConnection conn;
        try {
            conn = pool.acquire(target);
        } catch (IllegalArgumentException bad) {
            return errorResp(out, 400, "invalid_target", sanitizeMsg(safeMsg(bad)));
        } catch (Throwable t) {
            return errorResp(out, 502, "connection_failed",
                    "could not connect: " + sanitizeMsg(safeMsg(t)));
        }

        try {
            try {
                if (binaryFrame) {
                    conn.webSocket().sendBinary(ByteBuffer.wrap(body), true)
                            .orTimeout(timeoutMs, TimeUnit.MILLISECONDS).join();
                } else {
                    conn.webSocket().sendText(new String(body, StandardCharsets.UTF_8), true)
                            .orTimeout(timeoutMs, TimeUnit.MILLISECONDS).join();
                }
            } catch (Throwable t) {
                return errorResp(out, 502, "send_failed",
                        "send to target failed: " + sanitizeMsg(safeMsg(t)));
            }

            return wantAll ? aggregatedResponse(out, conn, timeoutMs)
                           : firstResponse(out, conn, timeoutMs);
        } finally {
            pool.release(conn);
        }
    }

    private Response firstResponse(Outcome out, PooledWsConnection conn, long timeoutMs) {
        Object item;
        try {
            item = conn.inbox.poll(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            return errorResp(out, 504, "timeout", "bridge interrupted");
        }
        if (item == null) {
            return errorResp(out, 504, "timeout", "no response within " + timeoutMs + " ms");
        }
        if (item instanceof PooledWsConnection.Closed closed) {
            return errorResp(out, 502, "connection_closed",
                    "server closed connection (code=" + closed.statusCode + ")");
        }
        if (item instanceof Throwable t) {
            return errorResp(out, 502, "listener_error", sanitizeMsg(safeMsg(t)));
        }
        if (item instanceof String s) {
            conn.noteConsumedBytes((long) s.length() * 2L);
            byte[] body = s.getBytes(StandardCharsets.UTF_8);
            out.statusCode = 200;
            out.responseContentType = "application/json; charset=utf-8";
            out.responseBody = body;
            out.responseHeaders.put(RESP_DIRECTION, "server-to-client");
            Response r = newFixedLengthResponse(statusOf(200, "OK"),
                    "application/json; charset=utf-8", s);
            r.addHeader(RESP_DIRECTION, "server-to-client");
            return r;
        }
        if (item instanceof byte[] b) {
            conn.noteConsumedBytes(b.length);
            out.statusCode = 200;
            out.responseContentType = "application/octet-stream";
            out.responseBody = b;
            out.responseHeaders.put(RESP_DIRECTION, "server-to-client");
            Response r = newFixedLengthResponse(statusOf(200, "OK"),
                    "application/octet-stream",
                    new java.io.ByteArrayInputStream(b), b.length);
            r.addHeader(RESP_DIRECTION, "server-to-client");
            return r;
        }
        return errorResp(out, 502, "unknown_item", "unknown inbox item type");
    }

    private Response aggregatedResponse(Outcome out, PooledWsConnection conn, long totalTimeoutMs) {
        long deadline = System.nanoTime() + totalTimeoutMs * 1_000_000L;
        // Audit fix: stream directly to a byte sink with a running cap. The previous
        // StringBuilder + sb.toString().getBytes() path materialised the JSON twice
        // (chars + UTF-8 bytes) — ~3× peak at the 32 MB cap. With this writer we
        // count actual UTF-8 bytes against MAX_REQUEST_BODY_BYTES and abort early.
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream(1024);
        baos.write('[');
        boolean first = true;
        boolean closedByServer = false;
        boolean truncated = false;
        while (System.nanoTime() < deadline) {
            long remainingNs = deadline - System.nanoTime();
            if (remainingNs <= 0) break;
            Object item;
            try {
                item = conn.inbox.poll(remainingNs, TimeUnit.NANOSECONDS);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                break;
            }
            if (item == null) break;
            if (item instanceof PooledWsConnection.Closed) {
                closedByServer = true;
                break;
            }
            if (item instanceof Throwable) {
                break;
            }
            byte[] chunk;
            if (item instanceof String s) {
                conn.noteConsumedBytes((long) s.length() * 2L);
                chunk = jsonString(s).getBytes(StandardCharsets.UTF_8);
            } else if (item instanceof byte[] b) {
                conn.noteConsumedBytes(b.length);
                String encoded = "\"" + Base64.getEncoder().encodeToString(b) + "\"";
                chunk = encoded.getBytes(StandardCharsets.UTF_8);
            } else {
                continue;
            }
            int needed = (first ? 0 : 1) + chunk.length;
            if (baos.size() + needed + 1 > MAX_REQUEST_BODY_BYTES) { // +1 for trailing ']'
                truncated = true;
                break;
            }
            if (!first) baos.write(',');
            first = false;
            try { baos.write(chunk); } catch (Throwable ignored) {}
        }
        baos.write(']');
        byte[] body = baos.toByteArray();
        out.statusCode = 200;
        out.responseContentType = "application/json";
        out.responseBody = body;
        out.responseHeaders.put(RESP_DIRECTION, "server-to-client");
        if (closedByServer) out.responseHeaders.put("X-COMINT-WS-Closed", "true");
        if (truncated) out.responseHeaders.put("X-COMINT-WS-Truncated", "true");
        Response r = newFixedLengthResponse(statusOf(200, "OK"), "application/json",
                new java.io.ByteArrayInputStream(body), body.length);
        r.addHeader(RESP_DIRECTION, "server-to-client");
        if (closedByServer) r.addHeader("X-COMINT-WS-Closed", "true");
        if (truncated) r.addHeader("X-COMINT-WS-Truncated", "true");
        return r;
    }

    /** NanoHTTPD's Response.Status enum lacks 502/504/508 — wrap in IStatus. */
    private static Response.IStatus statusOf(int code, String desc) {
        return new Response.IStatus() {
            @Override public int getRequestStatus() { return code; }
            @Override public String getDescription() { return code + " " + desc; }
        };
    }

    private static long parseTimeout(String header) {
        if (header == null || header.isEmpty()) return DEFAULT_TIMEOUT_MS;
        try {
            long v = Long.parseLong(header.trim());
            if (v < 1) return DEFAULT_TIMEOUT_MS;
            if (v > MAX_TIMEOUT_MS) return MAX_TIMEOUT_MS;
            return v;
        } catch (NumberFormatException nfe) {
            return DEFAULT_TIMEOUT_MS;
        }
    }

    private static boolean isBinaryContent(String contentType) {
        if (contentType == null) return false;
        String c = contentType.toLowerCase(java.util.Locale.ROOT);
        if (c.startsWith("application/octet-stream")) return true;
        if (c.startsWith("application/x-protobuf")) return true;
        if (c.startsWith("application/protobuf")) return true;
        if (c.startsWith("application/msgpack") || c.startsWith("application/x-msgpack")) return true;
        return false;
    }

    private static boolean isLoopbackIp(String remoteIp) {
        if (remoteIp == null || remoteIp.isEmpty()) return false;
        // Audit fix: hand the address to InetAddress so dual-stack JVMs that
        // produce ::ffff:127.0.0.1 (IPv4-mapped IPv6), abbreviated forms like
        // 0::1, or addresses with zone identifiers like ::1%lo0 are all
        // recognised. Strip any zone id first because some JDKs reject them
        // in getByName.
        String host = remoteIp;
        int pct = host.indexOf('%');
        if (pct > 0) host = host.substring(0, pct);
        try {
            return java.net.InetAddress.getByName(host).isLoopbackAddress();
        } catch (Throwable t) {
            // Conservative fallback to the literal-string list — preserves the
            // pre-fix behaviour rather than silently accepting non-loopback.
            if ("127.0.0.1".equals(host)) return true;
            if ("::1".equals(host)) return true;
            if ("0:0:0:0:0:0:0:1".equals(host)) return true;
            return host.startsWith("127.");
        }
    }

    private static String sanitizeMsg(String s) {
        if (s == null) return "";
        String t = s.replace('\r', ' ').replace('\n', ' ').replace('\t', ' ');
        if (t.length() > 200) t = t.substring(0, 200) + "...";
        return t;
    }

    private static String jsonString(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 2);
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        sb.append('"');
        return sb.toString();
    }

    private Response errorResp(Outcome out, int code, String errorKey, String message) {
        String payload = "{\"error\":" + jsonString(errorKey)
                + ",\"message\":" + jsonString(message) + "}";
        byte[] body = payload.getBytes(StandardCharsets.UTF_8);
        if (out != null) {
            out.statusCode = code;
            out.responseContentType = "application/json";
            out.responseBody = body;
        }
        return newFixedLengthResponse(statusOf(code, errorKey), "application/json", payload);
    }

    /**
     * Bugs 1+2: synthesize the HttpRequest/HttpResponse pair from the bridge's
     * incoming raw bytes and outgoing response state, then publish it to the
     * COMINT Traffic listener. This is the only path that puts bridge requests
     * into COMINT Traffic — Burp's HttpHandler doesn't see them because they
     * never leave the extension's JVM.
     */
    private void publishTrafficEntry(IHTTPSession session, Outcome out) {
        if (trafficListener == null || session == null || out == null) return;
        try {
            // ---- Synthesize request bytes ----
            byte[] reqBytes = synthesizeRequestBytes(session, out.requestBody);
            HttpService svc;
            try {
                svc = HttpService.httpService("127.0.0.1", boundPort, false);
            } catch (Throwable t) {
                logErr("HttpService.httpService: " + safeMsg(t));
                return;
            }
            HttpRequest req;
            try {
                req = HttpRequest.httpRequest(svc, ByteArray.byteArray(reqBytes));
            } catch (Throwable t) {
                logErr("HttpRequest.httpRequest: " + safeMsg(t));
                return;
            }

            // ---- Synthesize response bytes ----
            byte[] respBytes = synthesizeResponseBytes(out);
            HttpResponse resp;
            try {
                resp = HttpResponse.httpResponse(ByteArray.byteArray(respBytes));
            } catch (Throwable t) {
                logErr("HttpResponse.httpResponse: " + safeMsg(t));
                return;
            }

            // ---- Codec detection on request body ----
            String codecName = "None";
            if (codecRegistry != null) {
                try {
                    ProtocolCodec match = codecRegistry.codecForRequest(req).orElse(null);
                    if (match != null) codecName = match.name();
                } catch (Throwable ignored) {}
            }

            String url;
            try { url = req.url(); if (url == null) url = ""; }
            catch (Throwable t) { url = "http://127.0.0.1:" + boundPort + "/ws"; }

            ComintTrafficEntry entry = ComintTrafficEntry.builder()
                    .id(sharedCounter.incrementAndGet())
                    .timestamp(System.currentTimeMillis())
                    .kind(ComintTrafficEntry.Kind.HTTP)
                    .host("127.0.0.1:" + boundPort)
                    .method(safeMethod(session))
                    .url(url)
                    .protocol("WS-Bridge")
                    .codec(codecName)
                    .statusCode(out.statusCode)
                    .reason("")
                    .length(out.responseBody.length)
                    .httpRequest(req)
                    .httpResponse(resp)
                    .source("Bridge")
                    .build();
            trafficListener.onEntry(entry);
        } catch (Throwable t) {
            logErr("publishTrafficEntry failed: " + safeMsg(t));
        }
    }

    private static String safeMethod(IHTTPSession s) {
        try { return s.getMethod() == null ? "POST" : s.getMethod().toString(); }
        catch (Throwable t) { return "POST"; }
    }

    /** Build the request bytes Burp's editor expects: start-line + headers + CRLFCRLF + body. */
    private static byte[] synthesizeRequestBytes(IHTTPSession session, byte[] body) {
        if (body == null) body = new byte[0];
        StringBuilder sb = new StringBuilder(256 + body.length);
        String method = session.getMethod() == null ? "POST" : session.getMethod().toString();
        String uri = session.getUri() == null ? "/" : session.getUri();
        String qs = null;
        try { qs = session.getQueryParameterString(); } catch (Throwable ignored) {}
        sb.append(method).append(' ').append(uri);
        if (qs != null && !qs.isEmpty()) sb.append('?').append(qs);
        sb.append(" HTTP/1.1\r\n");
        Map<String, String> headers = session.getHeaders();
        if (headers != null) {
            for (Map.Entry<String, String> h : headers.entrySet()) {
                if (h.getKey() == null) continue;
                sb.append(h.getKey()).append(": ")
                        .append(h.getValue() == null ? "" : h.getValue()).append("\r\n");
            }
        }
        sb.append("\r\n");
        byte[] header = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = new byte[header.length + body.length];
        System.arraycopy(header, 0, full, 0, header.length);
        System.arraycopy(body, 0, full, header.length, body.length);
        return full;
    }

    private static byte[] synthesizeResponseBytes(Outcome out) {
        StringBuilder sb = new StringBuilder(128 + out.responseBody.length);
        sb.append("HTTP/1.1 ").append(out.statusCode).append(' ')
                .append(reasonForStatus(out.statusCode)).append("\r\n");
        sb.append("Content-Type: ").append(out.responseContentType).append("\r\n");
        sb.append("Content-Length: ").append(out.responseBody.length).append("\r\n");
        for (Map.Entry<String, String> h : out.responseHeaders.entrySet()) {
            if (h.getKey() == null) continue;
            sb.append(h.getKey()).append(": ")
                    .append(h.getValue() == null ? "" : h.getValue()).append("\r\n");
        }
        sb.append("\r\n");
        byte[] header = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = new byte[header.length + out.responseBody.length];
        System.arraycopy(header, 0, full, 0, header.length);
        System.arraycopy(out.responseBody, 0, full, header.length, out.responseBody.length);
        return full;
    }

    private static String reasonForStatus(int code) {
        return switch (code) {
            case 200 -> "OK";
            case 400 -> "Bad Request";
            case 403 -> "Forbidden";
            case 405 -> "Method Not Allowed";
            case 413 -> "Payload Too Large";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 504 -> "Gateway Timeout";
            case 508 -> "Loop Detected";
            default -> "OK";
        };
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT WS-Bridge: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }

    /** AsyncRunner that hands each ClientHandler to a fixed-size executor. */
    static final class FixedPoolRunner implements AsyncRunner {
        private final ExecutorService pool;
        private final Set<ClientHandler> running = ConcurrentHashMap.newKeySet();
        private final ReentrantLock shutdownLock = new ReentrantLock();

        FixedPoolRunner() {
            this.pool = Executors.newFixedThreadPool(HANDLER_THREADS, r -> {
                Thread t = new Thread(r, "comint-ws-bridge-handler");
                t.setDaemon(true);
                return t;
            });
        }

        @Override
        public void closeAll() {
            // Close any in-flight ClientHandlers; pool shutdown happens in shutdown().
            for (ClientHandler h : running) {
                try { h.close(); } catch (Throwable ignored) {}
            }
        }

        @Override
        public void closed(ClientHandler clientHandler) {
            running.remove(clientHandler);
        }

        @Override
        public void exec(ClientHandler clientHandler) {
            running.add(clientHandler);
            try {
                pool.submit(clientHandler);
            } catch (Throwable t) {
                running.remove(clientHandler);
                try { clientHandler.close(); } catch (Throwable ignored) {}
            }
        }

        void shutdown() {
            shutdownLock.lock();
            try {
                closeAll();
                pool.shutdownNow();
            } finally {
                shutdownLock.unlock();
            }
        }
    }

    // ---- test hooks ----
    static long parseTimeoutForTest(String header) { return parseTimeout(header); }
    static String jsonStringForTest(String s) { return jsonString(s); }
    static boolean isBinaryContentForTest(String ct) { return isBinaryContent(ct); }
    static boolean isLoopbackIpForTest(String ip) { return isLoopbackIp(ip); }

    @SuppressWarnings("unused")
    private static InetSocketAddress _silenceUnusedImport() { return null; }
}
