package com.comint.codec;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CodecRegistryTest {

    @Test
    void findCodecReturnsEmptyForNullRequestResponse() {
        CodecRegistry r = new CodecRegistry();
        r.register(new MessagePackCodec());
        assertEquals(Optional.empty(), r.findCodec(null));
    }

    @Test
    void findCodecPrefersRequestSideMatch() {
        CodecRegistry r = new CodecRegistry();
        r.register(new MessagePackCodec());

        HttpRequest req = mock(HttpRequest.class);
        lenient().when(req.headerValue("Content-Type")).thenReturn("application/msgpack");
        lenient().when(req.body()).thenReturn(null);

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(req);
        when(rr.response()).thenReturn(null);

        Optional<ProtocolCodec> match = r.findCodec(rr);
        assertTrue(match.isPresent());
        assertEquals("MessagePack", match.get().name());
    }

    @Test
    void findCodecFallsBackToResponseSide() {
        CodecRegistry r = new CodecRegistry();
        r.register(new MessagePackCodec());

        HttpRequest req = mock(HttpRequest.class);
        lenient().when(req.headerValue("Content-Type")).thenReturn("application/json");

        HttpResponse resp = mock(HttpResponse.class);
        lenient().when(resp.headerValue("Content-Type")).thenReturn("application/x-msgpack");

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(req);
        when(rr.response()).thenReturn(resp);

        Optional<ProtocolCodec> match = r.findCodec(rr);
        assertTrue(match.isPresent());
        assertEquals("MessagePack", match.get().name());
    }

    @Test
    void findCodecReturnsEmptyWhenNothingMatches() {
        CodecRegistry r = new CodecRegistry();
        r.register(new MessagePackCodec());

        HttpRequest req = mock(HttpRequest.class);
        lenient().when(req.headerValue("Content-Type")).thenReturn("text/html");

        HttpRequestResponse rr = mock(HttpRequestResponse.class);
        when(rr.request()).thenReturn(req);
        when(rr.response()).thenReturn(null);

        assertEquals(Optional.empty(), r.findCodec(rr));
    }
}
