package com.comint.editor;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class HttpMessageFormatterTest {

    @Test
    void bodyOffsetCrlf() {
        String msg = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody-content";
        int off = HttpMessageFormatter.bodyOffset(msg.getBytes(StandardCharsets.ISO_8859_1));
        assertEquals(msg.indexOf("body-content"), off);
    }

    @Test
    void bodyOffsetLf() {
        String msg = "GET / HTTP/1.1\nHost: example.com\n\nbody";
        int off = HttpMessageFormatter.bodyOffset(msg.getBytes(StandardCharsets.ISO_8859_1));
        assertEquals(msg.indexOf("body"), off);
    }

    @Test
    void bodyOffsetMissingReturnsNegative() {
        String msg = "GET / HTTP/1.1\r\nHost: example.com\r\n";
        int off = HttpMessageFormatter.bodyOffset(msg.getBytes(StandardCharsets.ISO_8859_1));
        assertEquals(-1, off);
    }

    @Test
    void bodyOffsetEmptyReturnsNegative() {
        assertEquals(-1, HttpMessageFormatter.bodyOffset(null));
        assertEquals(-1, HttpMessageFormatter.bodyOffset(new byte[0]));
    }

    @Test
    void extractBodyReadsFromSeparator() {
        byte[] msg = "POST / HTTP/1.1\r\nHost: x\r\n\r\nHELLO".getBytes(StandardCharsets.ISO_8859_1);
        byte[] body = HttpMessageFormatter.extractBody(msg);
        assertArrayEquals("HELLO".getBytes(StandardCharsets.ISO_8859_1), body);
    }

    @Test
    void extractBodyReturnsEmptyOnNoSeparator() {
        byte[] msg = "POST / HTTP/1.1\r\nHost: x\r\n".getBytes(StandardCharsets.ISO_8859_1);
        byte[] body = HttpMessageFormatter.extractBody(msg);
        assertArrayEquals(new byte[0], body);
    }

    @Test
    void updateContentLengthReplacesExisting() {
        byte[] headers = ("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nX-Custom: a\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] updated = HttpMessageFormatter.updateContentLength(headers, 42);
        String s = new String(updated, StandardCharsets.ISO_8859_1);
        assertTrue(s.contains("Content-Length: 42\r\n"), s);
        assertFalse(s.contains("Content-Length: 5"), s);
        assertTrue(s.contains("X-Custom: a\r\n"));
        assertTrue(s.endsWith("\r\n\r\n"));
    }

    @Test
    void updateContentLengthInsertsWhenMissing() {
        byte[] headers = ("POST / HTTP/1.1\r\nHost: x\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] updated = HttpMessageFormatter.updateContentLength(headers, 7);
        String s = new String(updated, StandardCharsets.ISO_8859_1);
        assertTrue(s.contains("Content-Length: 7\r\n"));
        assertTrue(s.endsWith("\r\n\r\n"));
    }

    @Test
    void updateContentLengthCaseInsensitive() {
        byte[] headers = ("POST / HTTP/1.1\r\ncontent-length: 0\r\n\r\n")
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] updated = HttpMessageFormatter.updateContentLength(headers, 99);
        String s = new String(updated, StandardCharsets.ISO_8859_1);
        // Original header replaced; only one Content-Length should appear.
        int count = 0;
        int idx = 0;
        String lower = s.toLowerCase();
        while ((idx = lower.indexOf("content-length:", idx)) != -1) { count++; idx++; }
        assertEquals(1, count, "exactly one Content-Length expected: " + s);
        assertTrue(s.contains("Content-Length: 99"));
    }

    @Test
    void reconstructWithEncodedBodyRoundTrip() {
        byte[] edited = ("POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nHELLO")
                .getBytes(StandardCharsets.ISO_8859_1);
        byte[] newBody = "WORLD!!".getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = HttpMessageFormatter.reconstructWithEncodedBody(edited, newBody);
        String s = new String(full, StandardCharsets.ISO_8859_1);
        assertTrue(s.contains("Content-Length: 7"), s);
        // Body extracted from the rebuilt message matches.
        assertArrayEquals(newBody, HttpMessageFormatter.extractBody(full));
    }

    @Test
    void reconstructWithoutSeparatorAddsOne() {
        byte[] edited = ("POST /api HTTP/1.1\r\nHost: x\r\n").getBytes(StandardCharsets.ISO_8859_1);
        byte[] body = "PAYLOAD".getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = HttpMessageFormatter.reconstructWithEncodedBody(edited, body);
        String s = new String(full, StandardCharsets.ISO_8859_1);
        assertTrue(s.contains("Content-Length: 7"));
        assertArrayEquals(body, HttpMessageFormatter.extractBody(full));
    }

    @Test
    void reconstructHandlesNullInputs() {
        byte[] full = HttpMessageFormatter.reconstructWithEncodedBody(null, null);
        assertNotNull(full);
        // Should at least include a Content-Length: 0 header line.
        assertTrue(new String(full, StandardCharsets.ISO_8859_1).contains("Content-Length: 0"));
    }
}
