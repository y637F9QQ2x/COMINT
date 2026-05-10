package com.comint.bridge;

import burp.api.montoya.MontoyaApi;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded WebSocket connection pool keyed by target URL.
 *
 * <ul>
 *   <li>Capped at {@link #MAX_CONNECTIONS} live entries.
 *   <li>Idle entries (no use for {@link #IDLE_TIMEOUT_NANOS}) are closed by a
 *       periodic sweeper using {@code tryLock()} so a busy connection is never
 *       closed mid-trip.
 *   <li>{@link #shutdown()} closes every entry and stops the sweeper —
 *       called from {@link com.comint.ComintExtension#extensionUnloaded()}.
 * </ul>
 */
public class WsConnectionPool {

    public static final int MAX_CONNECTIONS = 32;
    static final long IDLE_TIMEOUT_NANOS = 60L * 1_000_000_000L;
    private static final long SWEEPER_PERIOD_SECONDS = 5L;
    private static final long CONNECT_TIMEOUT_SECONDS = 5L;

    private final MontoyaApi api;
    private final ConcurrentHashMap<String, PooledWsConnection> pool = new ConcurrentHashMap<>();
    private final HttpClient httpClient;
    private final ScheduledExecutorService sweeper;
    private final AtomicLong evictionCounter = new AtomicLong();
    private volatile boolean shutDown = false;

    public WsConnectionPool(MontoyaApi api) {
        this.api = api;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                .build();
        this.sweeper = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "comint-ws-bridge-sweeper");
            t.setDaemon(true);
            return t;
        });
        this.sweeper.scheduleAtFixedRate(this::sweep,
                SWEEPER_PERIOD_SECONDS, SWEEPER_PERIOD_SECONDS, TimeUnit.SECONDS);
    }

    /**
     * Acquire (or open) the connection for {@code target}. The returned entry is
     * already locked — callers MUST call {@link #release(PooledWsConnection)} in
     * a {@code finally} block.
     *
     * @throws Exception when the WebSocket handshake fails
     */
    public PooledWsConnection acquire(String target) throws Exception {
        if (shutDown) throw new IllegalStateException("pool shut down");
        if (target == null) throw new IllegalArgumentException("target null");
        if (!target.startsWith("ws://") && !target.startsWith("wss://")) {
            throw new IllegalArgumentException("target must start with ws:// or wss://");
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            // Audit fix: cap enforcement runs OUTSIDE computeIfAbsent. Calling
            // pool.remove() inside the mapping function violates ConcurrentHashMap's
            // contract ("the computation … must not attempt to update any other
            // mappings") and risks bin-lock deadlocks under concurrent acquire.
            while (pool.size() >= MAX_CONNECTIONS) {
                if (!evictOldestIdle()) break;
            }
            // Audit fix: re-check shutDown right before computeIfAbsent. Without
            // this, a thread that passed the line-65 check before shutdown() flipped
            // the flag could install a new entry into the map AFTER shutdown's clear()
            // ran — leaking that connection's NIO resources.
            if (shutDown) throw new IllegalStateException("pool shut down");
            PooledWsConnection entry = pool.computeIfAbsent(target, this::tryConnect);
            if (entry == null) {
                throw new RuntimeException("WebSocket handshake failed for " + target);
            }
            entry.lock.lock();
            // If shutdown ran between computeIfAbsent and lock acquisition, drop the
            // entry we just minted and surface the error.
            if (shutDown) {
                try { entry.closeQuietly(); } catch (Throwable ignored) {}
                pool.remove(target, entry);
                entry.lock.unlock();
                throw new IllegalStateException("pool shut down");
            }
            // Re-check liveness once the lock is held — the sweeper may have closed it.
            if (!entry.isAlive()) {
                // Audit fix: previously the dead entry was just removed from the pool
                // map and we looped — but the underlying WebSocket's NIO resources
                // might still be open if the sweeper hadn't yet swept it. Close it.
                pool.remove(target, entry);
                try { entry.closeQuietly(); } catch (Throwable ignored) {}
                entry.lock.unlock();
                continue;
            }
            entry.lastUsedNanos.set(System.nanoTime());
            return entry;
        }
        throw new RuntimeException("could not establish connection to " + target);
    }

    /** Release a previously-acquired entry. Always paired with {@link #acquire}.
     *  Audit fix: drains the inbox before unlocking so the next caller of this
     *  pooled connection cannot read leftover frames from the previous request
     *  (server pushed late frames; aggregated mode left items behind). */
    public void release(PooledWsConnection entry) {
        if (entry == null) return;
        try {
            try { entry.drainInbox(); } catch (Throwable ignored) {}
            entry.lastUsedNanos.set(System.nanoTime());
        } finally {
            try { entry.lock.unlock(); } catch (Throwable ignored) {}
        }
    }

    private PooledWsConnection tryConnect(String target) {
        try {
            PooledWsConnection entry = new PooledWsConnection(target);
            WebSocket ws = httpClient.newWebSocketBuilder()
                    .connectTimeout(Duration.ofSeconds(CONNECT_TIMEOUT_SECONDS))
                    .buildAsync(URI.create(target), entry.listener())
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join();
            entry.setWebSocket(ws);
            return entry;
        } catch (Throwable t) {
            logErr("connect to " + target + ": " + safeMsg(t));
            return null;
        }
    }

    /** Evict one idle entry. Returns true on success — caller can loop to drop
     *  more if the pool is still over capacity (e.g. CAP shrunk at runtime). */
    private boolean evictOldestIdle() {
        String oldestKey = null;
        long oldestUsed = Long.MAX_VALUE;
        for (Map.Entry<String, PooledWsConnection> e : pool.entrySet()) {
            PooledWsConnection v = e.getValue();
            if (v == null) continue;
            // Only consider entries we can lock without blocking — never evict a busy one.
            if (!v.lock.tryLock()) continue;
            try {
                long u = v.lastUsedNanos.get();
                if (u < oldestUsed) {
                    oldestUsed = u;
                    oldestKey = e.getKey();
                }
            } finally {
                v.lock.unlock();
            }
        }
        if (oldestKey == null) return false;
        PooledWsConnection victim = pool.remove(oldestKey);
        if (victim != null) {
            evictionCounter.incrementAndGet();
            victim.closeQuietly();
            return true;
        }
        return false;
    }

    private void sweep() {
        if (shutDown) return;
        long now = System.nanoTime();
        Iterator<Map.Entry<String, PooledWsConnection>> it = pool.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<String, PooledWsConnection> e = it.next();
            PooledWsConnection v = e.getValue();
            if (v == null) { it.remove(); continue; }
            if (!v.lock.tryLock()) continue;        // never close a busy connection
            try {
                if (!v.isAlive()) {
                    it.remove();
                    v.closeQuietly();
                    continue;
                }
                if (now - v.lastUsedNanos.get() > IDLE_TIMEOUT_NANOS) {
                    it.remove();
                    v.closeQuietly();
                }
            } finally {
                v.lock.unlock();
            }
        }
    }

    public int size() { return pool.size(); }
    public long evictions() { return evictionCounter.get(); }

    public void shutdown() {
        shutDown = true;
        try { sweeper.shutdownNow(); } catch (Throwable ignored) {}
        // Audit fix: drain the map AFTER the flag is set so concurrent acquire
        // either (a) sees shutDown=true at the re-check before computeIfAbsent
        // and bails, or (b) installed an entry that we now find here and close.
        // Either way, every entry that ever entered the map gets closeQuietly.
        java.util.List<PooledWsConnection> snapshot = new java.util.ArrayList<>(pool.values());
        pool.clear();
        for (PooledWsConnection v : snapshot) {
            if (v == null) continue;
            try { v.closeQuietly(); } catch (Throwable ignored) {}
        }
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT WS-Bridge pool: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
