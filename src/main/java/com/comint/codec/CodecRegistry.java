package com.comint.codec;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class CodecRegistry {

    private final List<ProtocolCodec> codecs = new ArrayList<>();

    public void register(ProtocolCodec codec) {
        codecs.add(codec);
    }

    public List<ProtocolCodec> all() {
        return Collections.unmodifiableList(codecs);
    }

    public List<String> names() {
        return codecs.stream().map(ProtocolCodec::name).collect(Collectors.toList());
    }

    public Optional<ProtocolCodec> codecForRequest(HttpRequest request) {
        for (ProtocolCodec codec : codecs) {
            if (codec.isApplicableToRequest(request)) {
                return Optional.of(codec);
            }
        }
        return Optional.empty();
    }

    public Optional<ProtocolCodec> codecForResponse(HttpResponse response, HttpRequest associatedRequest) {
        for (ProtocolCodec codec : codecs) {
            if (codec.isApplicableToResponse(response, associatedRequest)) {
                return Optional.of(codec);
            }
        }
        return Optional.empty();
    }

    /**
     * Find the codec applicable to a request/response pair (R16). Prefers a
     * request-side match (which is how Repeater/Intruder/Scanner routes use
     * codecs), falling back to a response-side match for response-only flows
     * such as "Send to Comparer (Response)".
     */
    public Optional<ProtocolCodec> findCodec(HttpRequestResponse rr) {
        if (rr == null) return Optional.empty();
        HttpRequest req = null;
        HttpResponse resp = null;
        try { req = rr.request(); } catch (Throwable ignored) {}
        try { resp = rr.response(); } catch (Throwable ignored) {}
        if (req != null) {
            Optional<ProtocolCodec> reqCodec = codecForRequest(req);
            if (reqCodec.isPresent()) return reqCodec;
        }
        if (resp != null) {
            Optional<ProtocolCodec> respCodec = codecForResponse(resp, req);
            if (respCodec.isPresent()) return respCodec;
        }
        return Optional.empty();
    }
}
