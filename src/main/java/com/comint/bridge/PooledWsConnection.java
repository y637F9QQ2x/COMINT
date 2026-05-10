package com.comint.bridge;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * One pooled WebSocket connection. Holds the live {@link WebSocket}, an inbox
 * for received messages, and a per-connection lock that serialises send/recv
 * trips and protects against the idle-evictor closing a connection while a
 * handler is mid-operation.
 *
 * <p>The inbox is bounded to keep a chatty server from OOM-ing the bridge.
 * Each item is one of:
 * <ul>
 *   <li>{@link String} — a complete text message (may have arrived as fragments).
 *   <li>{@code byte[]} — a complete binary message.
 *   <li>{@link Closed} — the server (or our side) closed the connection.
 *   <li>{@link Throwable} — listener received an error.
 * </ul>
 */
final class PooledWsConnection {

    /** Inbox capacity per connection. Combined with {@link #MAX_BUFFERED_BYTES} it
     *  bounds memory while still allowing a burst of small messages. */
    static final int INBOX_CAPACITY = 256;
    /** Per-connection upper bound on accumulated message bytes still in the inbox. */
    static final int MAX_BUFFERED_BYTES = 32 * 1024 * 1024;

    /** Sentinel for connection-closed events posted to the inbox. */
    static final class Closed {
        final int statusCode;
        final String reason;
        Closed(int statusCode, String reason) {
            this.statusCode = statusCode;
            this.reason = reason == null ? "" : reason;
        }
    }

    final String target;
    final BlockingQueue<Object> inbox = new LinkedBlockingQueue<>(INBOX_CAPACITY);
    final ReentrantLock lock = new ReentrantLock();
    final AtomicLong lastUsedNanos = new AtomicLong(System.nanoTime());
    /** Total bytes of pending messages in the inbox. Used to enforce the 32 MB cap. */
    final AtomicLong bufferedBytes = new AtomicLong();

    private volatile WebSocket ws;

    PooledWsConnection(String target) {
        this.target = target;
    }

    void setWebSocket(WebSocket ws) { this.ws = ws; }
    WebSocket webSocket() { return ws; }

    /** True if the connection is still usable for new sends. */
    boolean isAlive() {
        WebSocket s = ws;
        if (s == null) return false;
        try {
            return !s.isInputClosed() && !s.isOutputClosed();
        } catch (Throwable t) {
            return false;
        }
    }

    /** Best-effort close. Falls back to {@code abort()} if the close future hangs. */
    void closeQuietly() {
        WebSocket s = ws;
        if (s == null) return;
        try {
            s.sendClose(WebSocket.NORMAL_CLOSURE, "idle")
                    .orTimeout(2, java.util.concurrent.TimeUnit.SECONDS)
                    .exceptionally(t -> { try { s.abort(); } catch (Throwable ignored) {} return s; });
        } catch (Throwable t) {
            try { s.abort(); } catch (Throwable ignored) {}
        }
    }

    /**
     * Build the {@link java.net.http.WebSocket.Listener} that posts received
     * messages to the inbox. Listener callbacks are non-reentrant per the JDK
     * Javadoc, but we still wrap each callback body in {@code try { ... } catch
     * (Throwable)} so a buffer-overflow / OOM in our offer logic can never
     * propagate up and silently kill the connection inside the JDK's NIO thread.
     */
    WebSocket.Listener listener() {
        return new WebSocket.Listener() {
            private final StringBuilder textBuf = new StringBuilder();
            private java.io.ByteArrayOutputStream binBuf;

            @Override public void onOpen(WebSocket webSocket) {
                try { webSocket.request(1); } catch (Throwable ignored) {}
            }

            @Override
            public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last) {
                try {
                    if (data != null) textBuf.append(data);
                    if (last) {
                        String full = textBuf.toString();
                        textBuf.setLength(0);
                        // Reject messages that would push the inbox past the byte cap;
                        // the cap is enforced even before we offer because the queue
                        // may already be full of moderately sized messages.
                        long size = (long) full.length() * 2L; // rough char-byte estimate
                        if (bufferedBytes.get() + size > MAX_BUFFERED_BYTES) {
                            inbox.offer(new Throwable("inbox full (32MB cap)"));
                        } else {
                            bufferedBytes.addAndGet(size);
                            inbox.offer(full);
                        }
                    }
                    webSocket.request(1);
                } catch (Throwable t) {
                    try { inbox.offer(t); } catch (Throwable ignored) {}
                }
                return null;
            }

            @Override
            public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last) {
                try {
                    if (data != null) {
                        if (binBuf == null) binBuf = new java.io.ByteArrayOutputStream(Math.max(64, data.remaining()));
                        byte[] chunk = new byte[data.remaining()];
                        data.get(chunk);
                        binBuf.write(chunk);
                    }
                    if (last && binBuf != null) {
                        byte[] full = binBuf.toByteArray();
                        binBuf = null;
                        if (bufferedBytes.get() + full.length > MAX_BUFFERED_BYTES) {
                            inbox.offer(new Throwable("inbox full (32MB cap)"));
                        } else {
                            bufferedBytes.addAndGet(full.length);
                            inbox.offer(full);
                        }
                    }
                    webSocket.request(1);
                } catch (Throwable t) {
                    try { inbox.offer(t); } catch (Throwable ignored) {}
                }
                return null;
            }

            @Override public void onError(WebSocket webSocket, Throwable error) {
                try { inbox.offer(error == null ? new Throwable("unknown listener error") : error); } catch (Throwable ignored) {}
            }

            @Override
            public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason) {
                try { inbox.offer(new Closed(statusCode, reason)); } catch (Throwable ignored) {}
                return null;
            }
        };
    }

    /** Subtract a previously-offered item's byte cost from the running total. */
    void noteConsumedBytes(long bytes) {
        if (bytes <= 0) return;
        bufferedBytes.addAndGet(-bytes);
    }

    /** Audit fix: drop everything still queued in the inbox so the next caller
     *  doesn't pick up frames from the previous request. Resets the byte counter
     *  too — leftover items would otherwise count against the next request's cap. */
    void drainInbox() {
        try {
            while (inbox.poll() != null) {
                // discard
            }
        } catch (Throwable ignored) {}
        try { bufferedBytes.set(0L); } catch (Throwable ignored) {}
    }
}
