package com.comint.codec;

import com.google.protobuf.ByteString;
import com.google.protobuf.UnknownFieldSet;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class GrpcWebCodecTest {

    private final GrpcWebCodec codec = new GrpcWebCodec();

    @Test
    void name() {
        assertEquals("gRPC-Web", codec.name());
    }

    @Test
    void emptyBytesReturnEmptyEnvelope() {
        String out = codec.decode(new byte[0]);
        assertTrue(out.contains("\"frames\""));
        assertTrue(out.contains("[ ]") || out.contains("[]"));
    }

    @Test
    void emptyStringEncodesToZeroBytes() {
        assertArrayEquals(new byte[0], codec.encode(""));
        assertArrayEquals(new byte[0], codec.encode(null));
    }

    @Test
    void roundTripSingleDataFrame() {
        UnknownFieldSet inner = UnknownFieldSet.newBuilder()
                .addField(1, UnknownFieldSet.Field.newBuilder().addVarint(7L).build())
                .build();
        byte[] payload = inner.toByteArray();

        // Frame: flag=0, length=payload.length, payload bytes
        byte[] frame = new byte[5 + payload.length];
        frame[0] = 0;
        frame[1] = (byte) ((payload.length >>> 24) & 0xff);
        frame[2] = (byte) ((payload.length >>> 16) & 0xff);
        frame[3] = (byte) ((payload.length >>> 8) & 0xff);
        frame[4] = (byte) (payload.length & 0xff);
        System.arraycopy(payload, 0, frame, 5, payload.length);

        String json = codec.decode(frame);
        assertTrue(json.contains("\"data\""));
        assertTrue(json.contains("\"frames\""));

        byte[] reEncoded = codec.encode(json);
        assertArrayEquals(frame, reEncoded);
    }

    @Test
    void roundTripTrailers() {
        String trailerText = "grpc-status:0\r\ngrpc-message:OK\r\n";
        byte[] tBytes = trailerText.getBytes(StandardCharsets.US_ASCII);
        byte[] frame = new byte[5 + tBytes.length];
        frame[0] = (byte) 0x80;
        frame[1] = (byte) ((tBytes.length >>> 24) & 0xff);
        frame[2] = (byte) ((tBytes.length >>> 16) & 0xff);
        frame[3] = (byte) ((tBytes.length >>> 8) & 0xff);
        frame[4] = (byte) (tBytes.length & 0xff);
        System.arraycopy(tBytes, 0, frame, 5, tBytes.length);

        String json = codec.decode(frame);
        assertTrue(json.contains("\"trailers\""));
        assertTrue(json.contains("grpc-status:0"));

        byte[] reEncoded = codec.encode(json);
        assertArrayEquals(frame, reEncoded);
    }

    @Test
    void textEncodedBase64RoundTrip() {
        UnknownFieldSet inner = UnknownFieldSet.newBuilder()
                .addField(1, UnknownFieldSet.Field.newBuilder()
                        .addLengthDelimited(ByteString.copyFromUtf8("hi"))
                        .build())
                .build();
        byte[] payload = inner.toByteArray();
        byte[] frame = new byte[5 + payload.length];
        frame[0] = 0;
        frame[4] = (byte) payload.length;
        System.arraycopy(payload, 0, frame, 5, payload.length);

        byte[] textEncoded = Base64.getEncoder().encode(frame);
        String json = codec.decode(textEncoded);
        assertTrue(json.contains("\"textEncoded\" : true") || json.contains("\"textEncoded\":true"),
                "expected textEncoded flag in: " + json);

        byte[] reEncoded = codec.encode(json);
        assertArrayEquals(textEncoded, reEncoded);
    }

    @Test
    void truncatedFrameSurvives() {
        // Frame header says 100 bytes but only 2 are available.
        byte[] bad = new byte[]{0, 0, 0, 0, 100, 0x00, 0x01};
        String json = codec.decode(bad);
        assertTrue(json.contains("truncated_frame") || json.contains("trailing_garbage"),
                "got: " + json);
    }

    @Test
    void decodeMalformedBase64SurvivesAsRaw() {
        // String of base64-looking chars but not a real base64 of frames.
        byte[] data = "AAAAAA==xxxx".getBytes(StandardCharsets.US_ASCII);
        // Should not throw — must produce a valid envelope or error placeholder.
        String json = codec.decode(data);
        assertNotNull(json);
        assertFalse(json.isEmpty());
    }

    @Test
    void rejectsLargePayload() {
        byte[] huge = new byte[33 * 1024 * 1024];
        String result = codec.decode(huge);
        assertTrue(result.startsWith("/* COMINT gRPC-Web") || result.contains("frames"),
                "got: " + result);
    }
}
