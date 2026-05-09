package com.comint.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;

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
    private final ConcurrentMap<Integer, Long> requestStartTimes = new ConcurrentHashMap<>();
    /** Hard cap on the pending-request map. Requests that never see a response would
     *  otherwise leak entries here forever; at the cap we evict the lowest message id
     *  to keep memory bounded during long sessions. */
    private static final int MAX_PENDING_REQUESTS = 4096;

    public ComintHttpHandler(MontoyaApi api,
                             CodecRegistry codecRegistry,
                             ComintTrafficListener listener,
                             AtomicInteger sharedCounter) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.listener = listener;
        this.entryCounter = sharedCounter != null ? sharedCounter : new AtomicInteger();
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        // PURE PASSTHROUGH. Decoding/encoding belongs only in the COMINT editor tab
        // (setRequestResponse / getRequest) and in scanner insertion points
        // (buildHttpRequestWithPayload). The HttpHandler must NEVER mutate bodies —
        // doing so corrupts Burp's stored representation and breaks Pretty/Raw views.
        try {
            if (requestToBeSent != null) {
                if (requestStartTimes.size() >= MAX_PENDING_REQUESTS) {
                    // Drop the lowest message id (oldest) to bound memory during long sessions.
                    Integer oldest = null;
                    for (Integer k : requestStartTimes.keySet()) {
                        if (oldest == null || k < oldest) oldest = k;
                    }
                    if (oldest != null) requestStartTimes.remove(oldest);
                }
                requestStartTimes.put(requestToBeSent.messageId(), System.currentTimeMillis());
            }
        } catch (Throwable t) {
            logErr("handleHttpRequestToBeSent: " + safeMsg(t));
        }
        return RequestToBeSentAction.continueWith(requestToBeSent);
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

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT HTTP: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
