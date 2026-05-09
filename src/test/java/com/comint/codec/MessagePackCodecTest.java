package com.comint.codec;

import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessagePackCodecTest {

    private final MessagePackCodec codec = new MessagePackCodec();

    @Test
    void roundTripSimpleMap() {
        // {"hello":"world","n":42}
        byte[] msgpack = new byte[]{
                (byte) 0x82,                                     // fixmap, 2 entries
                (byte) 0xa5, 'h', 'e', 'l', 'l', 'o',            // fixstr "hello"
                (byte) 0xa5, 'w', 'o', 'r', 'l', 'd',            // fixstr "world"
                (byte) 0xa1, 'n',                                // fixstr "n"
                (byte) 0x2a                                      // positive fixint 42
        };

        String json = codec.decode(msgpack);
        assertTrue(json.contains("\"hello\""), "decoded JSON should contain 'hello' key");
        assertTrue(json.contains("\"world\""), "decoded JSON should contain 'world' value");
        assertTrue(json.contains("42"), "decoded JSON should contain 42");

        byte[] reEncoded = codec.encode(json);
        // Re-decode and compare structurally — byte order of map keys is not guaranteed
        String json2 = codec.decode(reEncoded);
        assertEquals(json, json2, "decode is deterministic across round-trip");
    }

    @Test
    void name() {
        assertEquals("MessagePack", codec.name());
    }

    @Test
    void encodesEmptyArray() {
        byte[] encoded = codec.encode("[]");
        assertEquals(1, encoded.length);
        assertEquals((byte) 0x90, encoded[0]); // fixarray of size 0
    }

    @Test
    void decodeMalformedReturnsErrorComment() {
        String result = codec.decode(new byte[]{(byte) 0xc1}); // never-used type
        assertTrue(result.startsWith("/* COMINT MessagePack decode error"),
                "got: " + result);
    }

    @Test
    void roundTripArray() {
        byte[] encoded = codec.encode("[1,2,3]");
        byte[] expected = new byte[]{(byte) 0x93, 0x01, 0x02, 0x03};
        assertTrue(Arrays.equals(expected, encoded),
                "expected " + Arrays.toString(expected) + ", got " + Arrays.toString(encoded));
    }
}
