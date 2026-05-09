package com.comint.codec;

import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProtobufCodecTest {

    private final ProtobufCodec codec = new ProtobufCodec();

    @Test
    void name() {
        assertEquals("Protobuf", codec.name());
    }

    @Test
    void emptyDecodesToEmptyObject() {
        assertEquals("{}", codec.decode(new byte[0]));
        assertEquals("{}", codec.decode(null));
    }

    @Test
    void emptyEncodesToZeroBytes() {
        assertArrayEquals(new byte[0], codec.encode(""));
        assertArrayEquals(new byte[0], codec.encode("{}"));
        assertArrayEquals(new byte[0], codec.encode(null));
    }

    @Test
    void roundTripVarintAndString() throws Exception {
        UnknownFieldSet ufs = UnknownFieldSet.newBuilder()
                .addField(1, UnknownFieldSet.Field.newBuilder().addVarint(42L).build())
                .addField(2, UnknownFieldSet.Field.newBuilder()
                        .addLengthDelimited(ByteString.copyFromUtf8("hello"))
                        .build())
                .build();
        byte[] wire = ufs.toByteArray();

        String json = codec.decode(wire);
        assertTrue(json.contains("\"1\""), "decoded JSON should reference field 1: " + json);
        assertTrue(json.contains("\"varint\""));
        assertTrue(json.contains("42"));
        assertTrue(json.contains("\"string\""));
        assertTrue(json.contains("hello"));

        byte[] reEncoded = codec.encode(json);
        // Re-decode and confirm structurally identical (protobuf wire is canonical here).
        String json2 = codec.decode(reEncoded);
        assertEquals(json, json2, "round-trip must be lossless");
    }

    @Test
    void decodeMalformedReturnsErrorComment() {
        // Tag with wire type that requires more bytes than available.
        byte[] truncated = new byte[]{0x0a, 0x05, 0x00};
        String result = codec.decode(truncated);
        assertTrue(result.startsWith("/* COMINT Protobuf decode error"), "got: " + result);
    }

    @Test
    void encodeRefusesErrorPlaceholder() {
        assertThrows(RuntimeException.class,
                () -> codec.encode("/* COMINT Protobuf decode error: foo */"));
    }

    @Test
    void encodeRejectsInvalidFieldNumber() {
        String json = "{\"0\": [{\"type\": \"varint\", \"value\": 1}]}";
        assertThrows(RuntimeException.class, () -> codec.encode(json));
    }

    @Test
    void roundTripBytesField() {
        // A length-delimited field carrying non-UTF-8 bytes — decoded as base64 "bytes".
        byte[] randomBytes = new byte[]{(byte) 0xff, (byte) 0xfe, (byte) 0xfd, 0x01, 0x02};
        UnknownFieldSet ufs = UnknownFieldSet.newBuilder()
                .addField(1, UnknownFieldSet.Field.newBuilder()
                        .addLengthDelimited(ByteString.copyFrom(randomBytes))
                        .build())
                .build();
        byte[] wire = ufs.toByteArray();

        String json = codec.decode(wire);
        assertTrue(json.contains("\"bytes\""), "expected bytes type in JSON: " + json);

        byte[] reEncoded = codec.encode(json);
        String json2 = codec.decode(reEncoded);
        assertEquals(json, json2);
    }

    @Test
    void rejectsLargePayload() {
        // 33MB array — should bypass parse and emit size warning.
        byte[] huge = new byte[33 * 1024 * 1024];
        String result = codec.decode(huge);
        assertTrue(result.startsWith("/* COMINT Protobuf"), "got: " + result);
    }
}
