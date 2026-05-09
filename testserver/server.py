#!/usr/bin/env python3
"""
COMINT test server.

Exposes the five protocols COMINT decodes (WebSocket, MessagePack, Protobuf,
gRPC-Web, GraphQL) on a single aiohttp server bound to localhost:3000, plus an
HTML test page at / that triggers each endpoint from the browser so the traffic
flows through whichever proxy the browser is configured to use.

Run:
    pip install -r requirements.txt
    python server.py
"""

from __future__ import annotations

import base64
import json
import logging
import sys
from typing import Any

from aiohttp import WSMsgType, web
import msgpack

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

from graphql import build_schema, graphql_sync


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-5s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("comint-testserver")


# --------------------------------------------------------------------------- #
# Protobuf — dynamic User message (no .proto compilation)
# --------------------------------------------------------------------------- #
def _build_user_class():
    file_proto = descriptor_pb2.FileDescriptorProto()
    file_proto.name = "comint_test.proto"
    file_proto.syntax = "proto3"
    file_proto.package = "comint.test"

    msg = file_proto.message_type.add()
    msg.name = "User"

    fd = descriptor_pb2.FieldDescriptorProto
    field_specs = [
        ("id",    1, fd.TYPE_INT32,  fd.LABEL_OPTIONAL),
        ("name",  2, fd.TYPE_STRING, fd.LABEL_OPTIONAL),
        ("email", 3, fd.TYPE_STRING, fd.LABEL_OPTIONAL),
        ("tags",  4, fd.TYPE_STRING, fd.LABEL_REPEATED),
    ]
    for fname, fnum, ftype, flabel in field_specs:
        f = msg.field.add()
        f.name = fname
        f.number = fnum
        f.type = ftype
        f.label = flabel

    pool = descriptor_pool.DescriptorPool()
    pool.Add(file_proto)
    descriptor = pool.FindMessageTypeByName("comint.test.User")
    return message_factory.GetMessageClass(descriptor)


User = _build_user_class()


def user_to_dict(u) -> dict[str, Any]:
    return {"id": u.id, "name": u.name, "email": u.email, "tags": list(u.tags)}


def dict_to_user(d: dict[str, Any]):
    u = User()
    if d.get("id") is not None:
        u.id = int(d["id"])
    if d.get("name") is not None:
        u.name = str(d["name"])
    if d.get("email") is not None:
        u.email = str(d["email"])
    for tag in d.get("tags") or []:
        u.tags.append(str(tag))
    return u


# --------------------------------------------------------------------------- #
# gRPC-Web framing: [1 byte flags][4 bytes length BE][payload]
# --------------------------------------------------------------------------- #
def grpc_frame(payload: bytes, flags: int = 0x00) -> bytes:
    return bytes([flags]) + len(payload).to_bytes(4, "big") + payload


def grpc_unframe(data: bytes) -> bytes:
    if len(data) < 5:
        raise ValueError(f"gRPC frame too short: {len(data)} bytes")
    length = int.from_bytes(data[1:5], "big")
    end = 5 + length
    if end > len(data):
        raise ValueError(
            f"gRPC frame truncated: header says {length}, only {len(data) - 5} bytes after header"
        )
    return data[5:end]


# --------------------------------------------------------------------------- #
# GraphQL schema + in-memory data
# --------------------------------------------------------------------------- #
SCHEMA_SDL = """
type Query {
  user(id: ID!): User
  users: [User]
}

type Mutation {
  createUser(name: String!, email: String!): User
}

type User {
  id: ID!
  name: String!
  email: String!
  posts: [Post]
}

type Post {
  id: ID!
  title: String!
  body: String!
}
"""

_users_db: list[dict[str, Any]] = [
    {
        "id": "1", "name": "Alice", "email": "alice@example.com",
        "posts": [
            {"id": "p1", "title": "Welcome",          "body": "Hello, world!"},
            {"id": "p2", "title": "Notes on GraphQL", "body": "Resolvers are functions."},
        ],
    },
    {
        "id": "2", "name": "Bob", "email": "bob@example.com",
        "posts": [
            {"id": "p3", "title": "Fuzzing tactics", "body": "Mutate inputs systematically."},
        ],
    },
]

_schema = build_schema(SCHEMA_SDL)


def _create_user(name: str, email: str) -> dict[str, Any]:
    new_id = str(len(_users_db) + 1)
    user = {"id": new_id, "name": name, "email": email, "posts": []}
    _users_db.append(user)
    return user


def _exec_graphql(query: str, variables=None, operation_name=None):
    # graphql-core's default resolver: if source[field] is callable, call(info, **args).
    root = {
        "user": lambda info, id: next((u for u in _users_db if u["id"] == id), None),
        "users": lambda info: _users_db,
        "createUser": lambda info, name, email: _create_user(name, email),
    }
    return graphql_sync(
        _schema, query,
        root_value=root,
        variable_values=variables,
        operation_name=operation_name,
    )


# --------------------------------------------------------------------------- #
# Middlewares: CORS + request logging
# --------------------------------------------------------------------------- #
@web.middleware
async def cors_middleware(request: web.Request, handler):
    if request.method == "OPTIONS":
        return web.Response(
            status=204,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "*",
                "Access-Control-Max-Age": "86400",
            },
        )
    response = await handler(request)
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    response.headers.setdefault("Access-Control-Expose-Headers", "*")
    return response


@web.middleware
async def logging_middleware(request: web.Request, handler):
    ct = request.headers.get("Content-Type", "-")
    log.info("--> %s %s  CT=%s  len=%s",
             request.method, request.path_qs, ct, request.content_length)
    try:
        response = await handler(request)
    except Exception:
        log.exception("handler raised")
        raise
    log.info("<-- %s %s  status=%s  CT=%s",
             request.method, request.path_qs,
             response.status, response.headers.get("Content-Type", "-"))
    return response


# --------------------------------------------------------------------------- #
# Handlers
# --------------------------------------------------------------------------- #
MSGPACK_CTS = {"application/msgpack", "application/x-msgpack", "application/vnd.msgpack"}


def _content_type(request: web.Request) -> str:
    return (request.headers.get("Content-Type") or "").split(";")[0].strip().lower()


async def index(_request: web.Request) -> web.Response:
    return web.Response(text=INDEX_HTML, content_type="text/html")


async def samples(_request: web.Request) -> web.Response:
    """Pre-encoded sample bodies so the browser can POST realistic binary
    payloads without bundling msgpack/protobuf encoders in JS."""
    sample_user = {
        "id": 42, "name": "Carol", "email": "carol@example.com",
        "tags": ["admin", "tester"],
    }
    msgpack_bytes = msgpack.packb(sample_user)

    user = dict_to_user(sample_user)
    protobuf_bytes = user.SerializeToString()

    framed = grpc_frame(protobuf_bytes)

    return web.json_response({
        "user": sample_user,
        "msgpack_b64":        base64.b64encode(msgpack_bytes).decode("ascii"),
        "protobuf_b64":       base64.b64encode(protobuf_bytes).decode("ascii"),
        "grpc_web_text":      base64.b64encode(framed).decode("ascii"),
        "grpc_web_proto_b64": base64.b64encode(framed).decode("ascii"),
    })


async def msgpack_handler(request: web.Request) -> web.Response:
    ct = _content_type(request)
    body = await request.read()

    if ct in MSGPACK_CTS:
        try:
            decoded = msgpack.unpackb(body, raw=False)
        except Exception as e:
            return web.json_response({"error": f"msgpack decode failed: {e}"}, status=400)
    elif ct == "application/json":
        try:
            decoded = json.loads(body.decode("utf-8"))
        except Exception as e:
            return web.json_response({"error": f"json decode failed: {e}"}, status=400)
    else:
        return web.json_response(
            {"error": f"unsupported Content-Type: {ct!r}",
             "accepted": sorted(MSGPACK_CTS) + ["application/json"]},
            status=415,
        )

    log.info("    msgpack: decoded=%r", decoded)

    response_payload = {
        "echo": decoded,
        "server": "comint-testserver",
        "format": "msgpack",
    }
    return web.Response(
        body=msgpack.packb(response_payload),
        content_type="application/vnd.msgpack",
    )


async def protobuf_handler(request: web.Request) -> web.Response:
    ct = _content_type(request)
    if ct not in ("application/x-protobuf", "application/protobuf"):
        return web.json_response(
            {"error": f"expected application/x-protobuf, got {ct!r}"},
            status=415,
        )
    body = await request.read()
    try:
        u = User()
        u.ParseFromString(body)
    except Exception as e:
        return web.json_response({"error": f"protobuf parse failed: {e}"}, status=400)

    log.info("    protobuf: decoded=%s", user_to_dict(u))

    echo = User()
    echo.id = u.id + 1
    echo.name = u.name
    echo.email = u.email
    echo.tags.extend(u.tags)
    echo.tags.append("echoed")

    return web.Response(body=echo.SerializeToString(), content_type="application/x-protobuf")


async def grpc_web_handler(request: web.Request) -> web.Response:
    ct = _content_type(request)
    body = await request.read()

    if ct == "application/grpc-web-text":
        try:
            framed = base64.b64decode(body)
        except Exception as e:
            return web.json_response({"error": f"base64 decode failed: {e}"}, status=400)
    elif ct in ("application/grpc-web+proto", "application/grpc-web"):
        framed = body
    else:
        return web.json_response(
            {"error": f"unsupported Content-Type: {ct!r}",
             "accepted": ["application/grpc-web-text",
                          "application/grpc-web+proto",
                          "application/grpc-web"]},
            status=415,
        )

    try:
        payload = grpc_unframe(framed)
    except ValueError as e:
        return web.json_response({"error": f"grpc frame error: {e}"}, status=400)

    try:
        u = User()
        u.ParseFromString(payload)
    except Exception as e:
        return web.json_response({"error": f"protobuf parse failed: {e}"}, status=400)

    log.info("    grpc-web: decoded=%s", user_to_dict(u))

    echo = User()
    echo.id = u.id + 1
    echo.name = u.name
    echo.email = u.email
    echo.tags.extend(u.tags)
    echo.tags.append("echoed-grpc-web")

    out_frame = grpc_frame(echo.SerializeToString())
    if ct == "application/grpc-web-text":
        return web.Response(body=base64.b64encode(out_frame),
                            content_type="application/grpc-web-text")
    return web.Response(body=out_frame, content_type=ct)


async def graphql_handler(request: web.Request) -> web.Response:
    body = await request.read()
    try:
        envelope = json.loads(body.decode("utf-8"))
    except Exception as e:
        return web.json_response({"errors": [{"message": f"invalid JSON: {e}"}]}, status=400)

    query = envelope.get("query")
    if not query:
        return web.json_response({"errors": [{"message": "missing 'query' field"}]}, status=400)

    variables      = envelope.get("variables")
    operation_name = envelope.get("operationName")

    log.info("    graphql: op=%s vars=%s query=%r",
             operation_name, variables, query.replace("\n", " ")[:120])

    result = _exec_graphql(query, variables=variables, operation_name=operation_name)

    out: dict[str, Any] = {}
    if result.errors:
        out["errors"] = [
            {"message": e.message,
             "path": list(e.path) if e.path else None}
            for e in result.errors
        ]
    out["data"] = result.data
    return web.json_response(out)


async def websocket_handler(request: web.Request):
    fmt = request.query.get("format", "json").lower()
    if fmt not in ("json", "msgpack", "protobuf"):
        return web.Response(status=400,
                            text=f"unknown format {fmt!r}; use json|msgpack|protobuf")

    ws = web.WebSocketResponse()
    await ws.prepare(request)
    log.info("    websocket: client connected, format=%s", fmt)

    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            text = msg.data
            log.info("    ws TEXT in (%d): %s", len(text), text[:200])
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                data = {"raw": text}

            if fmt == "json":
                await ws.send_json({"echo": data, "format": "json",
                                    "server": "comint-testserver"})
            elif fmt == "msgpack":
                await ws.send_bytes(msgpack.packb(
                    {"echo": data, "format": "msgpack",
                     "server": "comint-testserver"}))
            else:  # protobuf
                src = data if isinstance(data, dict) else {"name": str(data)}
                u = dict_to_user(src)
                u.tags.append("ws-echo")
                await ws.send_bytes(u.SerializeToString())

        elif msg.type == WSMsgType.BINARY:
            log.info("    ws BINARY in (%d bytes)", len(msg.data))
            # Echo binary frames as-is.
            await ws.send_bytes(msg.data)

        elif msg.type == WSMsgType.ERROR:
            log.error("    ws error: %s", ws.exception())
            break

    log.info("    websocket: closed")
    return ws


# --------------------------------------------------------------------------- #
# HTML test page
# --------------------------------------------------------------------------- #
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>COMINT Test Server</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         max-width: 1100px; margin: 2em auto; padding: 0 1em; color: #222; }
  h1 { border-bottom: 2px solid #333; padding-bottom: .3em; }
  h1 small { font-size: .55em; color: #666; font-weight: normal; margin-left: 1em; }
  section { border: 1px solid #ccc; border-radius: 6px; padding: 1em;
            margin: 1em 0; background: #fafafa; }
  section h2 { margin-top: 0; font-size: 1.1em; color: #036; }
  button { padding: .45em .9em; margin: .2em; cursor: pointer;
           background: #036; color: white; border: 0; border-radius: 4px;
           font-size: 13px; }
  button:hover { background: #058; }
  pre { background: #fff; border: 1px solid #ddd; padding: .6em;
        border-radius: 4px; font-size: 12px; line-height: 1.4;
        overflow: auto; max-height: 260px; white-space: pre-wrap;
        word-break: break-all; }
  label { display: inline-block; margin-right: .5em; }
  select, input { padding: .3em; border: 1px solid #aaa; border-radius: 3px;
                  font-size: 13px; }
  .out-label { font-weight: bold; color: #555; margin-top: .5em;
               font-size: 11px; text-transform: uppercase; letter-spacing: .05em; }
  .row { display: flex; gap: 1em; flex-wrap: wrap; }
  .row > div { flex: 1; min-width: 320px; }
  code { background: #eee; padding: 1px 4px; border-radius: 3px; font-size: 90%; }
</style>
</head>
<body>
<h1>COMINT Test Server <small>localhost:3000</small></h1>
<p>Click each button to issue a request through the browser. To capture in Burp,
configure your browser to proxy through <code>127.0.0.1:8080</code>.</p>

<section>
  <h2>WebSocket — <code>ws://localhost:3000/ws/echo</code></h2>
  <label>Format:
    <select id="ws-format">
      <option value="json">json</option>
      <option value="msgpack">msgpack</option>
      <option value="protobuf">protobuf</option>
    </select>
  </label>
  <button onclick="wsConnect()">Connect</button>
  <button onclick="wsSend()">Send sample message</button>
  <button onclick="wsClose()">Close</button>
  <div class="out-label">Status</div>
  <pre id="ws-status">Not connected</pre>
  <div class="row">
    <div><div class="out-label">Sent</div><pre id="ws-sent"></pre></div>
    <div><div class="out-label">Received</div><pre id="ws-recv"></pre></div>
  </div>
</section>

<section>
  <h2>MessagePack — <code>POST /api/msgpack</code></h2>
  <button onclick="sendMsgpack()">Send msgpack body (vnd.msgpack)</button>
  <button onclick="sendMsgpackAlt('application/x-msgpack')">x-msgpack</button>
  <button onclick="sendMsgpackAlt('application/msgpack')">msgpack</button>
  <button onclick="sendMsgpackAsJson()">Same payload as JSON</button>
  <div class="row">
    <div><div class="out-label">Request</div><pre id="msgpack-req"></pre></div>
    <div><div class="out-label">Response</div><pre id="msgpack-resp"></pre></div>
  </div>
</section>

<section>
  <h2>Protocol Buffers — <code>POST /api/protobuf</code></h2>
  <button onclick="sendProtobuf()">Send protobuf body</button>
  <div class="row">
    <div><div class="out-label">Request</div><pre id="proto-req"></pre></div>
    <div><div class="out-label">Response</div><pre id="proto-resp"></pre></div>
  </div>
</section>

<section>
  <h2>gRPC-Web — <code>POST /api/grpc-web</code></h2>
  <button onclick="sendGrpcWebText()">grpc-web-text (Base64)</button>
  <button onclick="sendGrpcWebProto()">grpc-web+proto (binary)</button>
  <div class="row">
    <div><div class="out-label">Request</div><pre id="grpc-req"></pre></div>
    <div><div class="out-label">Response</div><pre id="grpc-resp"></pre></div>
  </div>
</section>

<section>
  <h2>GraphQL — <code>POST /graphql</code></h2>
  <button onclick="sendGraphQLAllUsers()">Query: users</button>
  <button onclick="sendGraphQLUserById()">Query: user(id: "1")</button>
  <button onclick="sendGraphQLMutation()">Mutation: createUser</button>
  <div class="row">
    <div><div class="out-label">Request</div><pre id="gql-req"></pre></div>
    <div><div class="out-label">Response</div><pre id="gql-resp"></pre></div>
  </div>
</section>

<script>
let SAMPLES = null;
let ws = null;

async function loadSamples() {
  const r = await fetch('/samples');
  SAMPLES = await r.json();
}
loadSamples();

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(bytes) {
  const lines = [];
  for (let i = 0; i < bytes.length; i += 16) {
    const slice = bytes.slice(i, i + 16);
    const hex = Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join(' ');
    const ascii = Array.from(slice).map(b => (b >= 0x20 && b < 0x7f) ? String.fromCharCode(b) : '.').join('');
    lines.push(i.toString(16).padStart(4, '0') + '  ' + hex.padEnd(48, ' ') + '  ' + ascii);
  }
  return lines.join('\n');
}

function bytesToText(bytes) {
  try { return new TextDecoder('utf-8', {fatal: false}).decode(bytes); }
  catch (e) { return ''; }
}

function showBinary(elId, bytes, contentType, label) {
  const el = document.getElementById(elId);
  el.textContent =
    `${label || 'BINARY'}\nContent-Type: ${contentType}\nLength: ${bytes.length} bytes\n\n` +
    bytesToHex(bytes) +
    `\n\n--- as text (lossy) ---\n` + bytesToText(bytes);
}

function showText(elId, text, contentType, label) {
  document.getElementById(elId).textContent =
    `${label || 'TEXT'}\nContent-Type: ${contentType}\n\n${text}`;
}

async function showResponse(elId, response) {
  const ct = response.headers.get('Content-Type') || '';
  const buf = await response.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const label = `HTTP ${response.status}`;
  if (ct.startsWith('application/json') || ct.startsWith('text/')) {
    let body = new TextDecoder().decode(bytes);
    if (ct.startsWith('application/json')) {
      try { body = JSON.stringify(JSON.parse(body), null, 2); } catch (e) {}
    }
    showText(elId, body, ct, label);
  } else {
    showBinary(elId, bytes, ct, label);
  }
}

// -------- WebSocket --------
function wsConnect() {
  if (ws && ws.readyState === WebSocket.OPEN) {
    document.getElementById('ws-status').textContent = 'already connected';
    return;
  }
  const fmt = document.getElementById('ws-format').value;
  ws = new WebSocket(`ws://${location.host}/ws/echo?format=${fmt}`);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => { document.getElementById('ws-status').textContent = `OPEN  format=${fmt}`; };
  ws.onclose = (e) => { document.getElementById('ws-status').textContent = `CLOSED  code=${e.code}`; };
  ws.onerror = ()  => { document.getElementById('ws-status').textContent = 'ERROR'; };
  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      let pretty = ev.data;
      try { pretty = JSON.stringify(JSON.parse(ev.data), null, 2); } catch (e) {}
      document.getElementById('ws-recv').textContent = `TEXT\n\n${pretty}`;
    } else {
      const bytes = new Uint8Array(ev.data);
      document.getElementById('ws-recv').textContent =
        `BINARY (${bytes.length} bytes)\n\n` + bytesToHex(bytes) +
        `\n\n--- as text (lossy) ---\n` + bytesToText(bytes);
    }
  };
}

function wsSend() {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    document.getElementById('ws-status').textContent = 'not connected — click Connect first';
    return;
  }
  const payload = {hello: 'comint', ts: Date.now(),
                   id: 7, name: 'WS user', email: 'ws@example.com',
                   tags: ['alpha', 'beta']};
  const text = JSON.stringify(payload);
  document.getElementById('ws-sent').textContent = text;
  ws.send(text);
}

function wsClose() { if (ws) ws.close(); }

// -------- REST --------
async function postBinary(url, ct, bytes) {
  return fetch(url, {method: 'POST', headers: {'Content-Type': ct}, body: bytes});
}

// MessagePack
async function sendMsgpackAlt(ct) {
  if (!SAMPLES) await loadSamples();
  const bytes = b64ToBytes(SAMPLES.msgpack_b64);
  showBinary('msgpack-req', bytes, ct);
  await showResponse('msgpack-resp', await postBinary('/api/msgpack', ct, bytes));
}
function sendMsgpack() { return sendMsgpackAlt('application/vnd.msgpack'); }

async function sendMsgpackAsJson() {
  if (!SAMPLES) await loadSamples();
  const text = JSON.stringify(SAMPLES.user, null, 2);
  showText('msgpack-req', text, 'application/json');
  const resp = await fetch('/api/msgpack', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(SAMPLES.user),
  });
  await showResponse('msgpack-resp', resp);
}

// Protobuf
async function sendProtobuf() {
  if (!SAMPLES) await loadSamples();
  const bytes = b64ToBytes(SAMPLES.protobuf_b64);
  showBinary('proto-req', bytes, 'application/x-protobuf');
  await showResponse('proto-resp',
    await postBinary('/api/protobuf', 'application/x-protobuf', bytes));
}

// gRPC-Web
async function sendGrpcWebText() {
  if (!SAMPLES) await loadSamples();
  const text = SAMPLES.grpc_web_text;
  const bytes = new TextEncoder().encode(text);
  showText('grpc-req', text, 'application/grpc-web-text',
           `BASE64 (decodes to ${bytes.length}-byte ASCII payload)`);
  await showResponse('grpc-resp',
    await postBinary('/api/grpc-web', 'application/grpc-web-text', bytes));
}

async function sendGrpcWebProto() {
  if (!SAMPLES) await loadSamples();
  const bytes = b64ToBytes(SAMPLES.grpc_web_proto_b64);
  showBinary('grpc-req', bytes, 'application/grpc-web+proto',
             'gRPC frame (5-byte header + protobuf payload)');
  await showResponse('grpc-resp',
    await postBinary('/api/grpc-web', 'application/grpc-web+proto', bytes));
}

// GraphQL
async function sendGraphQL(payload) {
  showText('gql-req', JSON.stringify(payload, null, 2), 'application/json');
  const resp = await fetch('/graphql', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  });
  await showResponse('gql-resp', resp);
}

function sendGraphQLAllUsers() {
  sendGraphQL({
    query: `query AllUsers {
  users {
    id
    name
    email
    posts { id title }
  }
}`,
    operationName: 'AllUsers',
  });
}

function sendGraphQLUserById() {
  sendGraphQL({
    query: `query GetUser($id: ID!) {
  user(id: $id) {
    id
    name
    email
    posts { id title body }
  }
}`,
    variables: {id: '1'},
    operationName: 'GetUser',
  });
}

function sendGraphQLMutation() {
  sendGraphQL({
    query: `mutation NewUser($name: String!, $email: String!) {
  createUser(name: $name, email: $email) {
    id name email
  }
}`,
    variables: {name: 'Mallory', email: 'mallory@example.com'},
    operationName: 'NewUser',
  });
}
</script>
</body>
</html>
"""


# --------------------------------------------------------------------------- #
# App + entry point
# --------------------------------------------------------------------------- #
def make_app() -> web.Application:
    app = web.Application(middlewares=[logging_middleware, cors_middleware])
    app.router.add_get ("/",             index)
    app.router.add_get ("/samples",      samples)
    app.router.add_post("/api/msgpack",  msgpack_handler)
    app.router.add_post("/api/protobuf", protobuf_handler)
    app.router.add_post("/api/grpc-web", grpc_web_handler)
    app.router.add_post("/graphql",      graphql_handler)
    app.router.add_get ("/ws/echo",      websocket_handler)
    return app


def main() -> None:
    app = make_app()
    log.info("COMINT test server starting on http://localhost:3000")
    log.info("  GET  /                — HTML test page")
    log.info("  GET  /samples         — pre-encoded sample bodies (base64)")
    log.info("  POST /api/msgpack     — MessagePack (or JSON) echo")
    log.info("  POST /api/protobuf    — Protobuf User echo")
    log.info("  POST /api/grpc-web    — gRPC-Web (text or +proto)")
    log.info("  POST /graphql         — GraphQL: users / user / createUser")
    log.info("  WS   /ws/echo         — WebSocket echo (?format=json|msgpack|protobuf)")
    web.run_app(app, host="0.0.0.0", port=3000, access_log=None)


if __name__ == "__main__":
    main()
