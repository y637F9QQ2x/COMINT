package com.comint.ui;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.websocket.Direction;

/**
 * Immutable entry representing a single line in the COMINT Traffic table.
 * Captures HTTP request/response pairs and individual WebSocket messages.
 */
public final class ComintTrafficEntry {

    public enum Kind { HTTP, WS_TEXT, WS_BINARY }

    public final int id;
    public final long timestamp;
    public final Kind kind;
    public final String host;
    public final String method;     // GET/POST/etc — or "WS →" / "WS ←"
    public final String url;
    public final String protocol;   // HTTP / WS / WSS
    public final String codec;      // codec name or "None"
    public final int statusCode;    // 0 for non-HTTP
    public final String reason;     // empty for non-HTTP
    public final int length;
    /** R25: originating Burp tool — "Proxy" / "Repeater" / "Intruder" / "Scanner" /
     *  "Extension" / "Bridge" / "WebSocket" / tool's own name for unknowns. */
    public final String source;

    public final HttpRequest httpRequest;
    public final HttpResponse httpResponse;
    public final HttpRequest wsUpgradeRequest;
    public final byte[] wsBinaryPayload;
    public final String wsTextPayload;
    public final Direction wsDirection;

    /** Mutable visibility flag (R13). Toggled by Hide selected / Unhide selected (R6). */
    private volatile boolean hidden;

    public boolean isHidden() { return hidden; }
    public void setHidden(boolean h) { this.hidden = h; }

    private ComintTrafficEntry(Builder b) {
        this.id = b.id;
        this.timestamp = b.timestamp;
        this.kind = b.kind;
        this.host = b.host == null ? "" : b.host;
        this.method = b.method == null ? "" : b.method;
        this.url = b.url == null ? "" : b.url;
        this.protocol = b.protocol == null ? "" : b.protocol;
        this.codec = b.codec == null ? "None" : b.codec;
        this.statusCode = b.statusCode;
        this.reason = b.reason == null ? "" : b.reason;
        this.length = b.length;
        this.source = b.source == null ? "" : b.source;
        this.httpRequest = b.httpRequest;
        this.httpResponse = b.httpResponse;
        this.wsUpgradeRequest = b.wsUpgradeRequest;
        this.wsBinaryPayload = b.wsBinaryPayload;
        this.wsTextPayload = b.wsTextPayload;
        this.wsDirection = b.wsDirection;
    }

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        int id;
        long timestamp = System.currentTimeMillis();
        Kind kind = Kind.HTTP;
        String host;
        String method;
        String url;
        String protocol;
        String codec;
        int statusCode;
        String reason;
        int length;
        String source;
        HttpRequest httpRequest;
        HttpResponse httpResponse;
        HttpRequest wsUpgradeRequest;
        byte[] wsBinaryPayload;
        String wsTextPayload;
        Direction wsDirection;

        public Builder id(int v) { this.id = v; return this; }
        public Builder timestamp(long v) { this.timestamp = v; return this; }
        public Builder kind(Kind v) { this.kind = v; return this; }
        public Builder host(String v) { this.host = v; return this; }
        public Builder method(String v) { this.method = v; return this; }
        public Builder url(String v) { this.url = v; return this; }
        public Builder protocol(String v) { this.protocol = v; return this; }
        public Builder codec(String v) { this.codec = v; return this; }
        public Builder statusCode(int v) { this.statusCode = v; return this; }
        public Builder reason(String v) { this.reason = v; return this; }
        public Builder length(int v) { this.length = v; return this; }
        public Builder source(String v) { this.source = v; return this; }
        public Builder httpRequest(HttpRequest v) { this.httpRequest = v; return this; }
        public Builder httpResponse(HttpResponse v) { this.httpResponse = v; return this; }
        public Builder wsUpgradeRequest(HttpRequest v) { this.wsUpgradeRequest = v; return this; }
        public Builder wsBinaryPayload(byte[] v) { this.wsBinaryPayload = v; return this; }
        public Builder wsTextPayload(String v) { this.wsTextPayload = v; return this; }
        public Builder wsDirection(Direction v) { this.wsDirection = v; return this; }

        public ComintTrafficEntry build() { return new ComintTrafficEntry(this); }
    }
}
