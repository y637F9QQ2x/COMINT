package com.comint.handler;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;

import javax.swing.JMenuItem;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * WS-8: COMINT extension's RawEditor tabs do not inherit Burp's native right-click
 * menu. Register this provider globally so right-clicking inside any message editor
 * (including COMINT's tabs in Repeater/Intruder/Proxy) gets the same Send-to-tool
 * options the COMINT Traffic table already provides.
 *
 * <p>All sends honour Requirement 16: when a codec applies, the body is decoded
 * before being handed off; for Repeater/Intruder the Content-Type is forced to
 * application/json so Burp's Auto§ detection can find JSON parameters.
 */
public final class ComintContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;

    public ComintContextMenuProvider(MontoyaApi api, CodecRegistry codecRegistry) {
        this.api = api;
        this.codecRegistry = codecRegistry;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event == null) return Collections.emptyList();
        HttpRequestResponse rr;
        try {
            Optional<MessageEditorHttpRequestResponse> mer = event.messageEditorRequestResponse();
            if (mer.isEmpty()) return Collections.emptyList();
            rr = mer.get().requestResponse();
        } catch (Throwable t) {
            return Collections.emptyList();
        }
        if (rr == null || rr.request() == null) return Collections.emptyList();

        final HttpRequest req = rr.request();
        final HttpResponse resp = rr.response();

        List<Component> items = new ArrayList<>();
        items.add(menuItem("COMINT — Send to Repeater", () -> {
            HttpRequest payload = decodeRequestForTool(req, true);
            api.repeater().sendToRepeater(payload);
        }));
        items.add(menuItem("COMINT — Send to Intruder", () -> {
            HttpRequest payload = decodeRequestForTool(req, true);
            api.intruder().sendToIntruder(payload);
        }));
        items.add(menuItem("COMINT — Send to Organizer", () -> {
            HttpRequest decReq = decodeRequestForTool(req, false);
            HttpResponse decResp = resp != null ? decodeResponseForTool(resp, req) : null;
            if (decResp != null) {
                api.organizer().sendToOrganizer(HttpRequestResponse.httpRequestResponse(decReq, decResp));
            } else {
                api.organizer().sendToOrganizer(decReq);
            }
        }));
        items.add(menuItem("COMINT — Send to Comparer (Request)", () -> {
            HttpRequest decReq = decodeRequestForTool(req, false);
            api.comparer().sendToComparer(decReq.toByteArray());
        }));
        if (resp != null) {
            items.add(menuItem("COMINT — Send to Comparer (Response)", () -> {
                HttpResponse decResp = decodeResponseForTool(resp, req);
                api.comparer().sendToComparer(decResp.toByteArray());
            }));
        }
        items.add(menuItem("COMINT — Do active scan", () -> {
            HttpRequest scanRequest = decodeRequestForTool(req, false);
            AuditConfiguration cfg = AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            Audit audit = api.scanner().startAudit(cfg);
            if (audit != null) audit.addRequest(scanRequest);
        }));
        return items;
    }

    private JMenuItem menuItem(String label, SafeRunnable r) {
        JMenuItem mi = new JMenuItem(label);
        mi.addActionListener(ev -> {
            try { r.run(); } catch (Throwable t) { logErr(label + ": " + safeMsg(t)); }
        });
        return mi;
    }

    @FunctionalInterface
    private interface SafeRunnable { void run() throws Throwable; }

    /** Decode the body via the matched codec; rebuild a clean HTTP/1.1 request.
     *  When forJson=true (Repeater/Intruder), the body is scrubbed and Content-Type
     *  is forced to application/json so Burp's Auto§ JSON detection lights up. */
    private HttpRequest decodeRequestForTool(HttpRequest req, boolean forJson) {
        if (req == null) return null;
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForRequest(req).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) return req;
        byte[] body = CodecUtil.safeBodyBytes(req);
        String decoded;
        try { decoded = codec.decode(body); }
        catch (Throwable t) { return req; }
        if (decoded == null) return req;
        byte[] decodedBytes = decoded.getBytes(StandardCharsets.UTF_8);
        try {
            // R10 (FIX 4): preserve the original Content-Type so ComintHttpHandler
            // can re-encode the JSON body back to the wire format on send.
            String origCt = CodecUtil.safeContentType(req);
            HttpRequest sanitized = req
                    .withRemovedHeader("Transfer-Encoding")
                    .withRemovedHeader("Content-Encoding");
            if (forJson) {
                sanitized = sanitized.withHeader("Content-Type", "application/json");
                if (origCt != null && !origCt.isEmpty()) {
                    sanitized = sanitized.withHeader("X-COMINT-Original-Content-Type", origCt);
                }
            }
            byte[] header = headerBytesOf(sanitized);
            byte[] full = new byte[header.length + decodedBytes.length];
            System.arraycopy(header, 0, full, 0, header.length);
            System.arraycopy(decodedBytes, 0, full, header.length, decodedBytes.length);
            // Update Content-Length in-place so Burp's parser sees the new body length.
            full = withContentLength(full, decodedBytes.length);
            HttpService svc = req.httpService();
            if (svc != null) {
                return HttpRequest.httpRequest(svc, ByteArray.byteArray(full));
            }
            return HttpRequest.httpRequest(ByteArray.byteArray(full));
        } catch (Throwable t) {
            logErr("decodeRequestForTool: " + safeMsg(t));
            return req;
        }
    }

    private HttpResponse decodeResponseForTool(HttpResponse resp, HttpRequest associatedRequest) {
        if (resp == null) return null;
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForResponse(resp, associatedRequest).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) return resp;
        byte[] body = CodecUtil.safeBodyBytes(resp);
        String decoded;
        try { decoded = codec.decode(body); }
        catch (Throwable t) { return resp; }
        if (decoded == null) return resp;
        byte[] decodedBytes = decoded.getBytes(StandardCharsets.UTF_8);
        try {
            HttpResponse sanitized = resp
                    .withRemovedHeader("Transfer-Encoding")
                    .withRemovedHeader("Content-Encoding");
            byte[] header = responseHeaderBytesOf(sanitized);
            byte[] full = new byte[header.length + decodedBytes.length];
            System.arraycopy(header, 0, full, 0, header.length);
            System.arraycopy(decodedBytes, 0, full, header.length, decodedBytes.length);
            full = withContentLength(full, decodedBytes.length);
            return HttpResponse.httpResponse(ByteArray.byteArray(full));
        } catch (Throwable t) {
            logErr("decodeResponseForTool: " + safeMsg(t));
            return resp;
        }
    }

    /** Header bytes (start-line + headers + CRLFCRLF) of an HttpRequest, without body. */
    private static byte[] headerBytesOf(HttpRequest req) {
        byte[] all = req.toByteArray().getBytes();
        int hdrEnd = findHeaderEnd(all);
        if (hdrEnd < 0) return all;
        byte[] out = new byte[hdrEnd];
        System.arraycopy(all, 0, out, 0, hdrEnd);
        return out;
    }

    private static byte[] responseHeaderBytesOf(HttpResponse resp) {
        byte[] all = resp.toByteArray().getBytes();
        int hdrEnd = findHeaderEnd(all);
        if (hdrEnd < 0) return all;
        byte[] out = new byte[hdrEnd];
        System.arraycopy(all, 0, out, 0, hdrEnd);
        return out;
    }

    private static int findHeaderEnd(byte[] msg) {
        for (int i = 0; i + 3 < msg.length; i++) {
            if (msg[i] == '\r' && msg[i + 1] == '\n' && msg[i + 2] == '\r' && msg[i + 3] == '\n') {
                return i + 4;
            }
        }
        return -1;
    }

    /** Replace or insert a Content-Length header that matches the new body length.
     *  Operates on the full message bytes. */
    private static byte[] withContentLength(byte[] msg, int bodyLen) {
        String header = new String(msg, 0, Math.min(msg.length, findHeaderEnd(msg) > 0
                ? findHeaderEnd(msg) : msg.length), StandardCharsets.ISO_8859_1);
        String[] lines = header.split("\r\n", -1);
        StringBuilder sb = new StringBuilder(header.length() + 32);
        boolean replaced = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (!replaced && line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                sb.append("Content-Length: ").append(bodyLen);
                replaced = true;
            } else if (i == lines.length - 2 && !replaced && line.isEmpty()) {
                // header section ends with empty line — insert before it
                sb.append("Content-Length: ").append(bodyLen).append("\r\n");
                sb.append(line);
                replaced = true;
            } else {
                sb.append(line);
            }
            if (i < lines.length - 1) sb.append("\r\n");
        }
        byte[] newHeader = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        int oldHdrEnd = findHeaderEnd(msg);
        if (oldHdrEnd < 0) return msg;
        int bodyStart = oldHdrEnd;
        int bodyBytes = msg.length - bodyStart;
        byte[] out = new byte[newHeader.length + bodyBytes];
        System.arraycopy(newHeader, 0, out, 0, newHeader.length);
        System.arraycopy(msg, bodyStart, out, newHeader.length, bodyBytes);
        return out;
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT ContextMenu: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
