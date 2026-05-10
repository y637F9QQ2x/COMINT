package com.comint.bridge;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BridgeRateLimiterTest {

    @Test
    void permitsAreCappedPerSecond() {
        // Bucket of 5 — the first 5 acquires succeed, the next is rejected
        // (refill is on a 1-second tick, which we don't wait for here).
        BridgeRateLimiter rl = new BridgeRateLimiter(5);
        try {
            for (int i = 0; i < 5; i++) {
                assertTrue(rl.tryAcquire(), "permit " + i + " should succeed");
            }
            assertFalse(rl.tryAcquire(), "6th permit must be rejected");
            assertEquals(1L, rl.rejected(), "rejected counter should advance");
        } finally {
            rl.shutdown();
        }
    }

    @Test
    void shutdownIsIdempotentAndDoesNotThrow() {
        BridgeRateLimiter rl = new BridgeRateLimiter(1);
        rl.shutdown();
        rl.shutdown();
    }
}
