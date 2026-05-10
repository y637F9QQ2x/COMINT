package com.comint.bridge;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.persistence.PersistedObject;

import com.comint.codec.CodecRegistry;
import com.comint.ui.ComintTrafficListener;

import fi.iki.elonen.NanoHTTPD;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Lifecycle wrapper for the embedded NanoHTTPD server that bridges HTTP requests
 * to outbound WebSocket calls. Bound exclusively to 127.0.0.1; the handler does
 * a second loopback check on each request as defence in depth.
 *
 * <p>Use {@link #start()} on extension load and {@link #shutdown()} on unload —
 * the latter closes every pooled WebSocket connection too.
 *
 * <p>Why NanoHTTPD and not {@code com.sun.net.httpserver}? Burp Suite's bundled
 * JRE does not include the {@code jdk.httpserver} module, so referring to that
 * class triggers {@code NoClassDefFoundError} on extension load.
 */
public class ComintWsBridge {

    public static final int DEFAULT_PORT = 8089;
    public static final String PERSISTENCE_PORT_KEY = "comint.bridge.port";
    public static final int REQUESTS_PER_SECOND = 100;
    private static final String LOOPBACK_HOSTNAME = "127.0.0.1";

    private final MontoyaApi api;
    private final WsConnectionPool pool;
    private final BridgeRateLimiter limiter;
    /** Bug 1+2: bridge handler publishes synthesized HttpRequest/HttpResponse rows
     *  to this listener so the COMINT Traffic table actually shows bridge requests
     *  (Burp's HttpHandler never sees them — they don't leave the JVM). Settable
     *  via {@link #setTrafficListener(ComintTrafficListener)} BEFORE {@link #start()}
     *  to break the construction cycle (the panel needs the bridge in its toolbar
     *  before the bridge can be told about the panel). */
    private ComintTrafficListener trafficListener;
    private final AtomicInteger sharedCounter;
    private final CodecRegistry codecRegistry;

    private final AtomicReference<ComintWsBridgeHandler> server = new AtomicReference<>();
    private volatile int currentPort;
    private volatile boolean running;

    public ComintWsBridge(MontoyaApi api) {
        this(api, null, null, null);
    }

    public ComintWsBridge(MontoyaApi api,
                          ComintTrafficListener trafficListener,
                          AtomicInteger sharedCounter,
                          CodecRegistry codecRegistry) {
        this.api = api;
        this.pool = new WsConnectionPool(api);
        this.limiter = new BridgeRateLimiter(REQUESTS_PER_SECOND);
        this.trafficListener = trafficListener;
        this.sharedCounter = sharedCounter;
        this.codecRegistry = codecRegistry;
        this.currentPort = loadSavedPort(api);
    }

    /** Inject the traffic listener after construction. Must be called before
     *  {@link #start()} — the running handler instance has already captured
     *  whatever listener was set at construction time. */
    public synchronized void setTrafficListener(ComintTrafficListener listener) {
        if (running) return;
        this.trafficListener = listener;
    }

    public synchronized boolean start() {
        if (running) return true;
        return start(currentPort);
    }

    public synchronized boolean start(int port) {
        if (running) {
            if (port == currentPort) return true;
            stop();
        }
        try {
            ComintWsBridgeHandler s = new ComintWsBridgeHandler(
                    api, LOOPBACK_HOSTNAME, port, pool, limiter,
                    trafficListener, sharedCounter, codecRegistry);
            // SOCKET_READ_TIMEOUT defaults to 5000 ms. daemon=false keeps the
            // listener thread alive across the extension's lifetime; we shut it
            // down explicitly in stop() / shutdown().
            s.start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
            server.set(s);
            currentPort = port;
            running = true;
            saveSavedPort(api, port);
            try { api.logging().logToOutput("COMINT WS-Bridge started on 127.0.0.1:" + port); }
            catch (Throwable ignored) {}
            return true;
        } catch (Throwable t) {
            try { api.logging().logToError("COMINT WS-Bridge start failed: " + safeMsg(t)); }
            catch (Throwable ignored) {}
            running = false;
            return false;
        }
    }

    public synchronized void stop() {
        running = false;
        ComintWsBridgeHandler s = server.getAndSet(null);
        if (s != null) {
            try { s.stop(); } catch (Throwable ignored) {}
        }
    }

    /** Full teardown — call on extension unload. */
    public synchronized void shutdown() {
        stop();
        try { pool.shutdown(); } catch (Throwable ignored) {}
        try { limiter.shutdown(); } catch (Throwable ignored) {}
    }

    public boolean isRunning() { return running; }
    public int port() { return currentPort; }
    public int activeConnections() { return pool.size(); }
    public long evictedConnections() { return pool.evictions(); }
    public long rejectedRequests() { return limiter.rejected(); }

    private static int loadSavedPort(MontoyaApi api) {
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext != null) {
                Integer saved = ext.getInteger(PERSISTENCE_PORT_KEY);
                if (saved != null && saved > 0 && saved < 65536) return saved;
            }
        } catch (Throwable ignored) {}
        return DEFAULT_PORT;
    }

    private static void saveSavedPort(MontoyaApi api, int port) {
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext != null) ext.setInteger(PERSISTENCE_PORT_KEY, port);
        } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
