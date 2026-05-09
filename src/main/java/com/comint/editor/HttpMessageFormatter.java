package com.comint.editor;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Formats and re-parses raw HTTP messages for the COMINT editor tabs.
 *
 * <p>Display layout (matches Burp's Pretty tab):
 * <pre>
 * METHOD PATH HTTP/1.1
 * Header1: Value1
 * Header2: Value2
 *
 * &lt;decoded body&gt;
 * </pre>
 *
 * <p>On encode, the body section is replaced with the codec-encoded bytes and
 * Content-Length is rewritten to match.
 */
public final class HttpMessageFormatter {

    /** ISO-8859-1 is the safe choice for HTTP/1.x headers (RFC 7230). */
    private static final java.nio.charset.Charset HEADER_CHARSET = StandardCharsets.ISO_8859_1;

    private HttpMessageFormatter() {}

    /** Builds the displayable bytes for a request: start line + headers + blank + decodedBody. */
    public static byte[] formatRequest(HttpRequest req, byte[] decodedBody) {
        if (req == null) return decodedBody == null ? new byte[0] : decodedBody;
        byte[] header = headerBytesForRequest(req);
        return concat(header, decodedBody == null ? new byte[0] : decodedBody);
    }

    /** Builds the displayable bytes for a response: status line + headers + blank + decodedBody. */
    public static byte[] formatResponse(HttpResponse resp, byte[] decodedBody) {
        if (resp == null) return decodedBody == null ? new byte[0] : decodedBody;
        byte[] header = headerBytesForResponse(resp);
        return concat(header, decodedBody == null ? new byte[0] : decodedBody);
    }

    private static byte[] headerBytesForRequest(HttpRequest req) {
        StringBuilder sb = new StringBuilder(256);
        String method = safe(req.method(), "GET");
        String path = safe(req.path(), "/");
        String version = safe(req.httpVersion(), "HTTP/1.1");
        sb.append(method).append(' ').append(path).append(' ').append(version).append("\r\n");
        List<HttpHeader> headers = null;
        try { headers = req.headers(); } catch (Throwable ignored) {}
        if (headers != null) {
            for (HttpHeader h : headers) {
                if (h == null) continue;
                String n = h.name();
                String v = h.value();
                if (n == null) n = "";
                if (v == null) v = "";
                sb.append(n).append(": ").append(v).append("\r\n");
            }
        }
        sb.append("\r\n");
        return sb.toString().getBytes(HEADER_CHARSET);
    }

    private static byte[] headerBytesForResponse(HttpResponse resp) {
        StringBuilder sb = new StringBuilder(256);
        String version = safe(resp.httpVersion(), "HTTP/1.1");
        short status;
        try { status = resp.statusCode(); } catch (Throwable t) { status = 0; }
        String reason = safe(resp.reasonPhrase(), "");
        // RFC 7230 §3.1.2: status-line = HTTP-version SP status-code SP reason-phrase CRLF.
        // Always emit the second SP, even when reason-phrase is empty.
        sb.append(version).append(' ').append((int) status & 0xffff).append(' ').append(reason).append("\r\n");
        List<HttpHeader> headers = null;
        try { headers = resp.headers(); } catch (Throwable ignored) {}
        if (headers != null) {
            for (HttpHeader h : headers) {
                if (h == null) continue;
                String n = h.name();
                String v = h.value();
                if (n == null) n = "";
                if (v == null) v = "";
                sb.append(n).append(": ").append(v).append("\r\n");
            }
        }
        sb.append("\r\n");
        return sb.toString().getBytes(HEADER_CHARSET);
    }

    /**
     * Find the byte offset of the body — the position immediately AFTER the empty
     * line separator (\r\n\r\n or \n\n). Returns -1 if not found.
     */
    public static int bodyOffset(byte[] data) {
        if (data == null || data.length < 2) return -1;
        for (int i = 0; i + 3 < data.length; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n'
                    && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < data.length; i++) {
            if (data[i] == '\n' && data[i + 1] == '\n') {
                return i + 2;
            }
        }
        return -1;
    }

    /**
     * Take the user-edited full message bytes (display form), replace the body section
     * with {@code encodedBody}, and rewrite Content-Length to match. Always emits the
     * canonical \r\n header form.
     */
    public static byte[] reconstructWithEncodedBody(byte[] editedFull, byte[] encodedBody) {
        if (encodedBody == null) encodedBody = new byte[0];
        if (editedFull == null) editedFull = new byte[0];
        int bodyOff = bodyOffset(editedFull);
        byte[] headerSection;
        if (bodyOff < 0) {
            // No separator — treat the entire thing as headers; we'll add a separator.
            headerSection = editedFull;
        } else {
            headerSection = new byte[bodyOff];
            System.arraycopy(editedFull, 0, headerSection, 0, bodyOff);
        }
        byte[] rewrittenHeaders = updateContentLength(headerSection, encodedBody.length);
        return concat(rewrittenHeaders, encodedBody);
    }

    /**
     * Rewrite (or insert) Content-Length to {@code newLength}. The resulting header
     * section ALWAYS ends with \r\n\r\n.
     */
    static byte[] updateContentLength(byte[] headerSection, int newLength) {
        String text = (headerSection == null || headerSection.length == 0)
                ? "" : new String(headerSection, HEADER_CHARSET);

        // Strip trailing blank line(s) so we control the terminator.
        while (text.endsWith("\r\n\r\n")) text = text.substring(0, text.length() - 2);
        while (text.endsWith("\n\n")) text = text.substring(0, text.length() - 1);
        if (text.endsWith("\r\n")) text = text.substring(0, text.length() - 2);
        else if (text.endsWith("\n")) text = text.substring(0, text.length() - 1);

        String[] lines = text.length() == 0 ? new String[0] : text.split("\\R", -1);
        StringBuilder out = new StringBuilder(text.length() + 32);
        boolean foundCL = false;

        if (lines.length > 0) {
            // Start line.
            out.append(lines[0]).append("\r\n");
            // Header lines.
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (line.length() >= 15 && line.regionMatches(true, 0, "Content-Length:", 0, 15)) {
                    out.append("Content-Length: ").append(newLength).append("\r\n");
                    foundCL = true;
                } else {
                    out.append(line).append("\r\n");
                }
            }
        }
        if (!foundCL) {
            out.append("Content-Length: ").append(newLength).append("\r\n");
        }
        out.append("\r\n");
        return out.toString().getBytes(HEADER_CHARSET);
    }

    /**
     * Extract the body section from the user-edited full message bytes.
     * Returns {@code new byte[0]} if no separator found.
     */
    public static byte[] extractBody(byte[] editedFull) {
        int off = bodyOffset(editedFull);
        if (off < 0) return new byte[0];
        if (off >= editedFull.length) return new byte[0];
        byte[] body = new byte[editedFull.length - off];
        System.arraycopy(editedFull, off, body, 0, body.length);
        return body;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static String safe(String s, String fallback) {
        return (s == null || s.isEmpty()) ? fallback : s;
    }
}
