# COMINT

**Communications Intelligence for Burp Suite**

Binary protocols shouldn't be a blind spot. COMINT decodes, edits, and re-encodes non-standard protocols so you can test them with Burp's native tools — Repeater, Intruder, Scanner — as if they were plain JSON.

---

## Supported Protocols

| Protocol | Content-Type | Decode |
|---|---|---|
| Protocol Buffers | `application/x-protobuf` | Black-box (no .proto needed) |
| gRPC-Web | `application/grpc-web-text`, `grpc-web+proto` | Base64 & binary |
| MessagePack | `application/vnd.msgpack` | Full round-trip |
| GraphQL | `application/json` (auto-detected) | Query pretty-print + variables |
| WebSocket | — | JSON / binary frame decode |

## How It Works

```
Browser/Client
    ↓ binary protocol
Burp Proxy (original bytes preserved)
    ↓
┌─────────────────────────────┐
│ COMINT Editor Tab            │
│ binary → decoded JSON        │
│ user edits freely            │
│ JSON → binary on send        │
└─────────────────────────────┘
    ↓ re-encoded binary
Target Server
```

You edit decoded JSON. COMINT re-encodes to the original wire format transparently. Scanner and Intruder payloads are injected into decoded fields and re-encoded automatically.

## Features

**COMINT Traffic** — Unified traffic log. HTTP and WebSocket in one chronological table. Filter, search, highlight by protocol, export logs.

**WS Bridge** — Embedded HTTP-to-WebSocket proxy. Fuzz and scan WebSocket endpoints using Repeater and Intruder, no external scripts needed.

**Transparent Re-encoding** — Edit in Repeater, fuzz in Intruder, scan with Scanner. COMINT handles the binary conversion behind the scenes.

**Multi-Language** — English · 日本語 · 한국어 · 简体中文 · 繁體中文 · Русский

## Installation

1. Download `comint-x.x.x.jar` from [Releases](../../releases)
2. Burp Suite → Extensions → Add → Select the JAR
3. Done. COMINT tabs appear automatically.

**Requirements:** Burp Suite 2026.2+ (Java 21 bundled)

## Quick Start

1. Browse your target app through Burp Proxy as usual
2. Binary protocol requests appear in **COMINT Traffic** with decoded content
3. Click any row → view decoded request/response with syntax highlighting
4. Right-click → Send to Repeater → edit decoded JSON → Send → COMINT re-encodes automatically
5. Right-click → Send to Intruder → Auto§ detects JSON parameters → fuzz binary protocol fields

### WebSocket Testing

1. WS Bridge starts automatically on `127.0.0.1:8089`
2. Send from Repeater:
```
POST /ws HTTP/1.1
Host: 127.0.0.1:8089
Content-Type: application/json
X-COMINT-WS-Target: ws://target.example.com/socket

{"action":"login","user":"admin","pass":"test"}
```
3. Bridge converts to WebSocket, returns the response as HTTP
4. Use Intruder/Scanner on the same request to fuzz WebSocket parameters

## Building from Source

```bash
git clone https://github.com/y637F9QQ2x/COMINT.git
cd COMINT
./gradlew shadowJar
# Output: build/libs/comint-x.x.x.jar
```

## License

MIT
