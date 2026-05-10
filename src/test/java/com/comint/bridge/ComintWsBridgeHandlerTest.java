package com.comint.bridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ComintWsBridgeHandlerTest {

    @Test
    void parseTimeoutDefaultsAndClamps() {
        // null / blank / non-numeric → default 5000.
        assertEquals(5000L, ComintWsBridgeHandler.parseTimeoutForTest(null));
        assertEquals(5000L, ComintWsBridgeHandler.parseTimeoutForTest(""));
        assertEquals(5000L, ComintWsBridgeHandler.parseTimeoutForTest("not-a-number"));
        // Within bounds — accepted.
        assertEquals(1500L, ComintWsBridgeHandler.parseTimeoutForTest("1500"));
        assertEquals(60000L, ComintWsBridgeHandler.parseTimeoutForTest("60000"));
        // Below 1 → default; above 60000 → clamped to 60000.
        assertEquals(5000L, ComintWsBridgeHandler.parseTimeoutForTest("0"));
        assertEquals(5000L, ComintWsBridgeHandler.parseTimeoutForTest("-1"));
        assertEquals(60000L, ComintWsBridgeHandler.parseTimeoutForTest("9999999"));
    }

    @Test
    void jsonStringEscapesControlAndQuotes() {
        assertEquals("\"hello\"", ComintWsBridgeHandler.jsonStringForTest("hello"));
        assertEquals("\"a\\\"b\"", ComintWsBridgeHandler.jsonStringForTest("a\"b"));
        assertEquals("\"a\\\\b\"", ComintWsBridgeHandler.jsonStringForTest("a\\b"));
        assertEquals("\"a\\nb\"", ComintWsBridgeHandler.jsonStringForTest("a\nb"));
        assertEquals("\"a\\u0001b\"", ComintWsBridgeHandler.jsonStringForTest("ab"));
    }

    @Test
    void binaryContentTypeDetection() {
        assertFalse(ComintWsBridgeHandler.isBinaryContentForTest(null));
        assertFalse(ComintWsBridgeHandler.isBinaryContentForTest("application/json"));
        assertFalse(ComintWsBridgeHandler.isBinaryContentForTest("text/plain"));
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("application/octet-stream"));
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("application/x-protobuf"));
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("application/protobuf"));
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("application/msgpack"));
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("application/x-msgpack"));
        // Case-insensitive prefix match.
        assertTrue(ComintWsBridgeHandler.isBinaryContentForTest("Application/Octet-Stream; charset=binary"));
    }
}
