package com.comint.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class WebSocketCodecTest {

    private final WebSocketCodec codec = new WebSocketCodec();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void name() {
        assertEquals("WebSocket", codec.name());
    }

    @Test
    void textJsonRoundTrip() throws Exception {
        String text = "{\"hello\":\"world\",\"n\":42}";
        String decoded = codec.decodeText(text);
        JsonNode env = mapper.readTree(decoded);
        assertEquals("json", env.get("kind").asText());

        String reEncoded = codec.encodeText(decoded);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("world", reParsed.get("hello").asText());
        assertEquals(42, reParsed.get("n").asInt());
    }

    @Test
    void plainTextRoundTrip() {
        String text = "hello, just some text";
        String decoded = codec.decodeText(text);
        assertTrue(decoded.contains("\"text\""));
        String reEncoded = codec.encodeText(decoded);
        assertEquals(text, reEncoded);
    }

    @Test
    void emptyTextRoundTrip() {
        String decoded = codec.decodeText("");
        assertNotNull(decoded);
        String reEncoded = codec.encodeText(decoded);
        assertEquals("", reEncoded);
    }

    @Test
    void graphqlWsEnvelopeDetected() throws Exception {
        String text = "{\"id\":\"1\",\"type\":\"subscribe\",\"payload\":{\"query\":\"{ ping }\",\"variables\":{}}}";
        String decoded = codec.decodeText(text);
        JsonNode env = mapper.readTree(decoded);
        assertEquals("graphql_ws", env.get("kind").asText());
        assertNotNull(env.get("envelope"));

        String reEncoded = codec.encodeText(decoded);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("subscribe", reParsed.get("type").asText());
        assertEquals("{ ping }", reParsed.get("payload").get("query").asText());
    }

    @Test
    void binaryMsgpackRoundTrip() throws Exception {
        // {"k":1} as msgpack
        byte[] msgpack = new byte[]{(byte) 0x81, (byte) 0xa1, 'k', 0x01};
        String decoded = codec.decodeBinary(msgpack);
        JsonNode env = mapper.readTree(decoded);
        assertEquals("msgpack", env.get("kind").asText());

        byte[] reEncoded = codec.encodeBinary(decoded);
        assertArrayEquals(msgpack, reEncoded);
    }

    @Test
    void binaryUnknownFallsBackToBase64() throws Exception {
        byte[] arbitrary = new byte[]{(byte) 0xff, (byte) 0xfe, (byte) 0x00, (byte) 0x42, (byte) 0xc1};
        String decoded = codec.decodeBinary(arbitrary);
        JsonNode env = mapper.readTree(decoded);
        assertEquals("binary", env.get("kind").asText());

        byte[] reEncoded = codec.encodeBinary(decoded);
        assertArrayEquals(arbitrary, reEncoded);
    }

    @Test
    void binaryEmpty() {
        String decoded = codec.decodeBinary(new byte[0]);
        assertNotNull(decoded);
        assertTrue(decoded.contains("binary_empty"));
        byte[] reEncoded = codec.encodeBinary(decoded);
        assertArrayEquals(new byte[0], reEncoded);
    }

    @Test
    void rejectsLargeText() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 33 * 1024 * 1024 + 1; i++) sb.append('a');
        String result = codec.decodeText(sb.toString());
        assertTrue(result.startsWith("/* COMINT WebSocket"), "got: " + result.substring(0, Math.min(80, result.length())));
    }

    @Test
    void rejectsLargeBinary() {
        byte[] huge = new byte[33 * 1024 * 1024];
        String result = codec.decodeBinary(huge);
        assertTrue(result.startsWith("/* COMINT WebSocket"), "got: " + result);
    }

    @Test
    void encodeRefusesErrorPlaceholder() {
        assertThrows(RuntimeException.class,
                () -> codec.encodeText("/* COMINT decode error */"));
        assertThrows(RuntimeException.class,
                () -> codec.encodeBinary("/* COMINT decode error */"));
    }

    @Test
    void textNullRoundTrip() {
        String decoded = codec.decodeText(null);
        assertNotNull(decoded);
        // Should not throw on encode either.
        String reEncoded = codec.encodeText(decoded);
        assertEquals("", reEncoded);
    }

    @Test
    void utf8TextNotMisidentified() {
        String text = "héllo wörld 你好";
        String decoded = codec.decodeText(text);
        // Plain UTF-8 string — should be wrapped as "text".
        assertTrue(decoded.contains("\"text\""));
        String reEncoded = codec.encodeText(decoded);
        assertEquals(text, reEncoded);
    }

    @SuppressWarnings("unused")
    private static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
