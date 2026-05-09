package com.comint.codec;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import graphql.language.AstPrinter;
import graphql.language.Document;
import graphql.parser.Parser;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * GraphQL codec.
 *
 * <p>Display: only the pretty-printed GraphQL query body — no metadata,
 * envelope markers, or operationName labels. The query alone is what the
 * security engineer sees and edits.
 *
 * <p>Round-trip: when the original body is a JSON envelope (single object or
 * batch) the codec preserves variables/operationName/extensions/extra by
 * editing only the {@code query} field of the original envelope (via
 * {@link #encode(String, byte[])}). The {@code originalBody}-less encode falls
 * back to a minimal {@code {"query": "..."}} envelope.
 */
public class GraphQLCodec implements ProtocolCodec {

    private static final int MAX_PAYLOAD_BYTES = 32 * 1024 * 1024;
    private static final String[] GRAPHQL_PATH_HINTS = {"/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql", "/query"};

    private final ObjectMapper jsonMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);
    private final ObjectMapper compactMapper = new ObjectMapper();

    @Override
    public String name() {
        return "GraphQL";
    }

    @Override
    public boolean isApplicableToRequest(HttpRequest request) {
        try {
            String ct = CodecUtil.safeContentType(request);
            if (CodecUtil.contentTypeContains(ct, "application/graphql")) return true;

            String path = CodecUtil.safePath(request);
            String method = CodecUtil.safeMethod(request);
            boolean pathHint = false;
            for (String hint : GRAPHQL_PATH_HINTS) {
                if (CodecUtil.pathContains(path, hint)) { pathHint = true; break; }
            }

            if ("GET".equals(method)) {
                if (pathHint) return hasQueryParam(request);
                return false;
            }

            boolean jsonish = CodecUtil.contentTypeContains(ct, "application/json")
                    || CodecUtil.contentTypeContains(ct, "+json");
            if (!jsonish && !pathHint) return false;

            int len = CodecUtil.safeBodyLength(request);
            if (len <= 0) return false;
            byte[] body = CodecUtil.safeBodyBytes(request);
            return bodyLooksLikeGraphQL(body);
        } catch (Throwable t) {
            return false;
        }
    }

    @Override
    public boolean isApplicableToResponse(HttpResponse response, HttpRequest associatedRequest) {
        return false;
    }

    private boolean hasQueryParam(HttpRequest request) {
        try {
            List<ParsedHttpParameter> params = request.parameters();
            if (params == null) return false;
            for (ParsedHttpParameter p : params) {
                if (p == null) continue;
                String n = p.name();
                if ("query".equals(n)) return true;
            }
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    private boolean bodyLooksLikeGraphQL(byte[] body) {
        if (body == null || body.length == 0) return false;
        int i = 0;
        while (i < body.length && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n')) i++;
        if (i >= body.length) return false;
        byte first = body[i];
        if (first != '{' && first != '[') return false;
        try {
            JsonNode root = jsonMapper.readTree(body);
            if (root == null) return false;
            if (root.isObject()) return root.has("query") || hasPersistedQuery(root);
            if (root.isArray()) {
                for (JsonNode el : root) {
                    if (el != null && el.isObject() && (el.has("query") || hasPersistedQuery(el))) return true;
                }
            }
            return false;
        } catch (Throwable t) {
            return false;
        }
    }

    private boolean hasPersistedQuery(JsonNode obj) {
        if (obj == null) return false;
        JsonNode ext = obj.get("extensions");
        if (ext == null || !ext.isObject()) return false;
        JsonNode pq = ext.get("persistedQuery");
        return pq != null && pq.isObject();
    }

    @Override
    public String decode(byte[] data) {
        if (data == null || data.length == 0) return "";
        if (data.length > MAX_PAYLOAD_BYTES) {
            return "/* COMINT GraphQL: payload too large (" + data.length + " bytes) */";
        }
        try {
            int i = 0;
            while (i < data.length && (data[i] == ' ' || data[i] == '\t' || data[i] == '\r' || data[i] == '\n')) i++;
            if (i >= data.length) return "";
            byte first = data[i];

            if (first == '{') {
                JsonNode root;
                try {
                    root = jsonMapper.readTree(data);
                } catch (Throwable t) {
                    return renderBlocks(prettyQuery(new String(data, StandardCharsets.UTF_8)), null, null);
                }
                if (root == null || !root.isObject()) {
                    return renderBlocks(prettyQuery(new String(data, StandardCharsets.UTF_8)), null, null);
                }
                return renderEnvelope((ObjectNode) root);
            }
            if (first == '[') {
                // Batch: display only the first operation; round-trip preserves the rest.
                JsonNode root;
                try {
                    root = jsonMapper.readTree(data);
                } catch (Throwable t) {
                    return renderBlocks(prettyQuery(new String(data, StandardCharsets.UTF_8)), null, null);
                }
                if (root != null && root.isArray() && root.size() > 0) {
                    JsonNode op0 = root.get(0);
                    if (op0 != null && op0.isObject()) {
                        return renderEnvelope((ObjectNode) op0);
                    }
                }
                return "";
            }
            // Raw-query body (application/graphql) — no envelope, just the query.
            return renderBlocks(prettyQuery(new String(data, StandardCharsets.UTF_8)), null, null);
        } catch (Throwable t) {
            try {
                return renderBlocks(prettyQuery(new String(data, StandardCharsets.UTF_8)), null, null);
            } catch (Throwable ignored) {
                return "/* COMINT GraphQL decode error: " + safeMsg(t) + " */";
            }
        }
    }

    /** Render the full GraphQL envelope as block-marker text for the editor. */
    private String renderEnvelope(ObjectNode envelope) {
        String query = "";
        JsonNode q = envelope.get("query");
        if (q != null && q.isTextual()) {
            query = prettyQuery(q.asText());
        }
        JsonNode varsNode = envelope.get("variables");
        String varsText = null;
        if (varsNode != null && !varsNode.isNull()) {
            try {
                varsText = jsonMapper.writeValueAsString(varsNode);
            } catch (Throwable ignored) {
                varsText = String.valueOf(varsNode);
            }
        }
        JsonNode opNode = envelope.get("operationName");
        String opName = null;
        if (opNode != null && opNode.isTextual() && !opNode.asText().isEmpty()) {
            opName = opNode.asText();
        }
        return renderBlocks(query, varsText, opName);
    }

    private String renderBlocks(String query, String varsText, String operationName) {
        StringBuilder sb = new StringBuilder();
        sb.append("[query]\n");
        if (query != null) sb.append(query);
        if (sb.length() > 0 && sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
        if (varsText != null) {
            sb.append('\n');
            sb.append("[variables]\n");
            sb.append(varsText);
            if (sb.charAt(sb.length() - 1) != '\n') sb.append('\n');
        }
        if (operationName != null) {
            sb.append('\n');
            sb.append("[operationName]\n");
            sb.append(operationName);
            sb.append('\n');
        }
        return sb.toString();
    }

    /** Parser output for the [query]/[variables]/[operationName] block format. */
    private static class ParsedBlocks {
        String query = "";
        boolean queryPresent = false;
        String varsText = null;
        boolean varsPresent = false;
        String operationName = null;
        boolean operationNamePresent = false;
    }

    /**
     * Parse the user-edited block format back into structured fields. Tolerates
     * blank lines, missing sections, and mixed line endings.
     */
    static ParsedBlocks parseBlocks(String text) {
        ParsedBlocks p = new ParsedBlocks();
        if (text == null || text.isEmpty()) return p;
        String[] lines = text.split("\\R", -1);
        StringBuilder buf = new StringBuilder();
        String currentBlock = null;
        for (String line : lines) {
            String trimmed = line.trim();
            String marker = blockMarker(trimmed);
            if (marker != null) {
                flushBlock(p, currentBlock, buf);
                buf.setLength(0);
                currentBlock = marker;
                continue;
            }
            if (currentBlock != null) {
                if (buf.length() > 0) buf.append('\n');
                buf.append(line);
            }
        }
        flushBlock(p, currentBlock, buf);
        return p;
    }

    private static String blockMarker(String trimmed) {
        if ("[query]".equals(trimmed)) return "query";
        if ("[variables]".equals(trimmed)) return "variables";
        if ("[operationName]".equals(trimmed)) return "operationName";
        return null;
    }

    private static void flushBlock(ParsedBlocks p, String block, StringBuilder buf) {
        if (block == null) return;
        // Strip trailing whitespace/blank lines but keep internal whitespace intact.
        String content = buf.toString();
        while (!content.isEmpty()) {
            char c = content.charAt(content.length() - 1);
            if (c == '\n' || c == '\r' || c == ' ' || c == '\t') {
                content = content.substring(0, content.length() - 1);
            } else {
                break;
            }
        }
        switch (block) {
            case "query":
                p.query = content;
                p.queryPresent = true;
                break;
            case "variables":
                p.varsText = content;
                p.varsPresent = true;
                break;
            case "operationName":
                p.operationName = content.trim();
                p.operationNamePresent = true;
                break;
            default:
                break;
        }
    }

    private String prettyQuery(String raw) {
        if (raw == null) return "";
        String trimmed = raw.trim();
        if (trimmed.isEmpty()) return "";
        try {
            Document doc = Parser.parse(trimmed);
            String pretty = AstPrinter.printAst(doc);
            return pretty == null ? trimmed : pretty;
        } catch (Throwable t) {
            return raw;
        }
    }

    private String minifyOrKeep(String maybePretty) {
        if (maybePretty == null) return "";
        String trimmed = maybePretty.trim();
        if (trimmed.isEmpty()) return "";
        try {
            Document doc = Parser.parse(trimmed);
            String compact = AstPrinter.printAstCompact(doc);
            return compact == null ? trimmed : compact;
        } catch (Throwable t) {
            // User's query is malformed mid-edit — preserve verbatim so a fuzz payload still goes through.
            return maybePretty;
        }
    }

    @Override
    public byte[] encode(String readable) {
        // Stateless fallback when the editor doesn't supply the original body.
        if (readable == null) return new byte[0];
        String trimmed = readable.trim();
        if (trimmed.isEmpty()) return new byte[0];
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("GraphQL encode: refusing to encode error placeholder");
        }
        try {
            ParsedBlocks p = parseBlocks(readable);
            ObjectNode env = compactMapper.createObjectNode();
            // If no [query] marker, treat the whole text as a raw query (backward-compat
            // for raw GraphQL bodies that arrive without any envelope structure).
            String queryText = p.queryPresent ? p.query : readable;
            env.put("query", minifyOrKeep(queryText));
            applyParsedExtras(env, p);
            return compactMapper.writeValueAsBytes(env);
        } catch (Throwable t) {
            throw new RuntimeException("GraphQL encode failed: " + safeMsg(t), t);
        }
    }

    private void applyParsedExtras(ObjectNode env, ParsedBlocks p) {
        if (p.varsPresent) {
            JsonNode parsedVars = parseJsonOrText(p.varsText);
            if (parsedVars != null) env.set("variables", parsedVars);
        }
        if (p.operationNamePresent && p.operationName != null && !p.operationName.isEmpty()) {
            env.put("operationName", p.operationName);
        }
    }

    private JsonNode parseJsonOrText(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        try {
            return jsonMapper.readTree(t);
        } catch (Throwable ignored) {
            // User typed something that doesn't parse — fall back to a string node so
            // the round-trip doesn't lose their input.
            return jsonMapper.getNodeFactory().textNode(s);
        }
    }

    @Override
    public byte[] encode(String readable, byte[] originalBody) {
        if (readable == null) readable = "";
        String trimmed = readable.trim();
        if (trimmed.startsWith("/*")) {
            throw new RuntimeException("GraphQL encode: refusing to encode error placeholder");
        }
        ParsedBlocks p = parseBlocks(readable);
        // No original body — fall back to a minimal JSON envelope built from the blocks,
        // or raw query bytes if there are no markers at all.
        if (originalBody == null || originalBody.length == 0) {
            if (trimmed.isEmpty()) return new byte[0];
            if (!p.queryPresent && !p.varsPresent && !p.operationNamePresent) {
                return readable.getBytes(StandardCharsets.UTF_8);
            }
            try {
                ObjectNode env = compactMapper.createObjectNode();
                env.put("query", minifyOrKeep(p.queryPresent ? p.query : readable));
                applyParsedExtras(env, p);
                return compactMapper.writeValueAsBytes(env);
            } catch (Throwable t) {
                throw new RuntimeException("GraphQL encode failed: " + safeMsg(t), t);
            }
        }
        try {
            int i = 0;
            while (i < originalBody.length
                    && (originalBody[i] == ' ' || originalBody[i] == '\t'
                    || originalBody[i] == '\r' || originalBody[i] == '\n')) i++;
            if (i >= originalBody.length) {
                return readable.getBytes(StandardCharsets.UTF_8);
            }
            byte first = originalBody[i];
            String userQuery = minifyOrKeep(p.queryPresent ? p.query : readable);

            if (first == '{') {
                JsonNode root;
                try {
                    root = jsonMapper.readTree(originalBody);
                } catch (Throwable t) {
                    return readable.getBytes(StandardCharsets.UTF_8);
                }
                if (root != null && root.isObject()) {
                    ObjectNode envelope = (ObjectNode) root.deepCopy();
                    // If the original was a persisted-query-only envelope (no inline `query`)
                    // and the user typed no query, leave it alone — don't inject `query: ""`
                    // which can defeat persisted-query semantics on some servers.
                    if (!userQuery.isEmpty() || envelope.has("query")) {
                        envelope.put("query", userQuery);
                    }
                    mergeBlocksIntoEnvelope(envelope, p);
                    return compactMapper.writeValueAsBytes(envelope);
                }
                return readable.getBytes(StandardCharsets.UTF_8);
            }
            if (first == '[') {
                JsonNode root;
                try {
                    root = jsonMapper.readTree(originalBody);
                } catch (Throwable t) {
                    return readable.getBytes(StandardCharsets.UTF_8);
                }
                if (root != null && root.isArray() && root.size() > 0) {
                    ArrayNode arr = (ArrayNode) root.deepCopy();
                    JsonNode op0 = arr.get(0);
                    if (op0 != null && op0.isObject()) {
                        ObjectNode envelope = (ObjectNode) op0;
                        envelope.put("query", userQuery);
                        mergeBlocksIntoEnvelope(envelope, p);
                    }
                    return compactMapper.writeValueAsBytes(arr);
                }
                return readable.getBytes(StandardCharsets.UTF_8);
            }
            // Raw query body in original (application/graphql) — there's no envelope to
            // merge variables into; emit just the user's query text.
            return userQuery.getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            throw e;
        } catch (Throwable t) {
            throw new RuntimeException("GraphQL encode failed: " + safeMsg(t), t);
        }
    }

    /** Merge user-edited variables/operationName blocks into an existing envelope. */
    private void mergeBlocksIntoEnvelope(ObjectNode envelope, ParsedBlocks p) {
        if (p.varsPresent) {
            JsonNode parsedVars = parseJsonOrText(p.varsText);
            if (parsedVars == null) {
                envelope.remove("variables");
            } else {
                envelope.set("variables", parsedVars);
            }
        }
        if (p.operationNamePresent) {
            String op = p.operationName;
            if (op == null || op.isEmpty()) {
                envelope.remove("operationName");
            } else {
                envelope.put("operationName", op);
            }
        }
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
