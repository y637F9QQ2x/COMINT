package com.comint.bridge;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Token bucket: at most {@code permitsPerSecond} requests per second.
 * Implemented with a {@link Semaphore} bounded at the per-second rate, refilled
 * once per second by a {@link ScheduledExecutorService}. {@link #tryAcquire()}
 * returns {@code false} when the bucket is empty so the caller can return 429
 * instead of blocking.
 */
final class BridgeRateLimiter {

    private final Semaphore permits;
    private final int capacity;
    private final ScheduledExecutorService refill;
    private final AtomicInteger rejectedCount = new AtomicInteger();

    BridgeRateLimiter(int permitsPerSecond) {
        this.capacity = Math.max(1, permitsPerSecond);
        this.permits = new Semaphore(capacity);
        this.refill = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "comint-ws-bridge-rate-refill");
            t.setDaemon(true);
            return t;
        });
        this.refill.scheduleAtFixedRate(this::topUp, 1, 1, TimeUnit.SECONDS);
    }

    boolean tryAcquire() {
        boolean ok = permits.tryAcquire();
        if (!ok) rejectedCount.incrementAndGet();
        return ok;
    }

    long rejected() { return rejectedCount.get(); }

    private void topUp() {
        // Re-fill back up to capacity, never overshoot.
        int missing = capacity - permits.availablePermits();
        if (missing > 0) permits.release(missing);
    }

    void shutdown() {
        try { refill.shutdownNow(); } catch (Throwable ignored) {}
    }
}
