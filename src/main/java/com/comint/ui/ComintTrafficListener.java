package com.comint.ui;

/**
 * Sink for traffic events captured by the HTTP and WebSocket handlers.
 * Implementations are responsible for thread-safety; {@link ComintTrafficPanel}
 * marshals to the EDT internally.
 */
public interface ComintTrafficListener {
    void onEntry(ComintTrafficEntry entry);
}
