package com.comint.codec;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class GraphQLCodecTest {

    private final GraphQLCodec codec = new GraphQLCodec();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void name() {
        assertEquals("GraphQL", codec.name());
    }

    @Test
    void emptyBodyDecodesToEmptyString() {
        assertEquals("", codec.decode(new byte[0]));
        assertEquals("", codec.decode(null));
    }

    @Test
    void displayShowsQueryVariablesAndOperationName() {
        String body = "{\"query\":\"query GetUser($id: ID!) { user(id: $id) { name email } }\"," +
                "\"variables\":{\"id\":\"42\"}," +
                "\"operationName\":\"GetUser\"}";
        String decoded = codec.decode(body.getBytes(StandardCharsets.UTF_8));
        // Real newlines, not JSON-escaped.
        assertTrue(decoded.contains("\n"), "decoded should contain newlines");
        assertFalse(decoded.contains("\\n"), "decoded should NOT contain JSON-escaped \\n: " + decoded);
        // All three blocks must be present.
        assertTrue(decoded.contains("[query]"), decoded);
        assertTrue(decoded.contains("[variables]"), decoded);
        assertTrue(decoded.contains("[operationName]"), decoded);
        // Variables visible as pretty JSON.
        assertTrue(decoded.contains("\"id\""), decoded);
        assertTrue(decoded.contains("\"42\""), decoded);
        // Operation name visible.
        assertTrue(decoded.contains("GetUser"), decoded);
        // Pretty-printed query body.
        assertTrue(decoded.contains("user("), decoded);
        // R4-prohibited decorations are NOT present.
        assertFalse(decoded.contains("=== COMINT GraphQL ==="), decoded);
        assertFalse(decoded.contains("Envelope:"), decoded);
        assertFalse(decoded.contains("--- Operation"), decoded);
        assertFalse(decoded.contains("operationName: GetUser"), decoded);
    }

    @Test
    void displayOmitsBlocksThatAreAbsent() {
        String body = "{\"query\":\"{ ping }\"}";
        String decoded = codec.decode(body.getBytes(StandardCharsets.UTF_8));
        assertTrue(decoded.contains("[query]"));
        assertFalse(decoded.contains("[variables]"));
        assertFalse(decoded.contains("[operationName]"));
    }

    @Test
    void roundTripPreservesVariablesAndOperationName() throws Exception {
        String body = "{\"query\":\"query GetUser($id: ID!) { user(id: $id) { name email } }\"," +
                "\"variables\":{\"id\":\"42\"}," +
                "\"operationName\":\"GetUser\"}";
        byte[] originalBody = body.getBytes(StandardCharsets.UTF_8);
        String decoded = codec.decode(originalBody);
        byte[] reEncoded = codec.encode(decoded, originalBody);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("GetUser", reParsed.get("operationName").asText());
        assertEquals("42", reParsed.get("variables").get("id").asText());
        assertTrue(reParsed.get("query").asText().contains("user"));
    }

    @Test
    void editVariablesRoundTripsThroughEnvelope() throws Exception {
        String body = "{\"query\":\"{ ping }\",\"variables\":{\"x\":1}}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        // User adds a variable in the [variables] block.
        String userEdit = "[query]\n{ ping }\n\n[variables]\n{ \"x\": 1, \"y\": \"new\" }\n";
        byte[] reEncoded = codec.encode(userEdit, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals(1, reParsed.get("variables").get("x").asInt());
        assertEquals("new", reParsed.get("variables").get("y").asText());
    }

    @Test
    void editOperationNameRoundTrips() throws Exception {
        String body = "{\"query\":\"{ a }\",\"operationName\":\"OldName\"}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String userEdit = "[query]\n{ a }\n\n[operationName]\nNewName\n";
        byte[] reEncoded = codec.encode(userEdit, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("NewName", reParsed.get("operationName").asText());
    }

    @Test
    void preservesUnknownTopLevelFields() throws Exception {
        String body = "{\"query\":\"{ ping }\",\"customField\":\"keep me\",\"foo\":42}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String decoded = codec.decode(orig);
        byte[] reEncoded = codec.encode(decoded, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("keep me", reParsed.get("customField").asText());
        assertEquals(42, reParsed.get("foo").asInt());
    }

    @Test
    void persistedQueryHashOnlyPreservedOnEncode() throws Exception {
        String body = "{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"abc\"}}}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String decoded = codec.decode(orig);
        // No `query`/`variables`/`operationName` fields present — display has only an empty [query] block.
        assertFalse(decoded.contains("[variables]"), decoded);
        assertFalse(decoded.contains("[operationName]"), decoded);
        // Round-trip: hash preserved; we DO NOT inject an empty `query` field.
        byte[] reEncoded = codec.encode(decoded, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("abc",
                reParsed.get("extensions").get("persistedQuery").get("sha256Hash").asText());
        assertFalse(reParsed.has("query"),
                "must not inject empty query field when original had none: " + reParsed);
    }

    @Test
    void batchDisplaysFirstOperationOnly() throws Exception {
        String body = "[{\"query\":\"{ a }\",\"variables\":{\"k\":1}},{\"query\":\"{ b }\"}]";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String decoded = codec.decode(orig);
        // First operation's query AND its variables are shown.
        assertTrue(decoded.contains("[query]"));
        assertTrue(decoded.contains("[variables]"));
        assertTrue(decoded.contains("\"k\""));
        byte[] reEncoded = codec.encode(decoded, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertTrue(reParsed.isArray());
        assertEquals(2, reParsed.size());
        assertTrue(reParsed.get(1).get("query").asText().contains("b"));
    }

    @Test
    void rawQueryBodyRoundTrip() {
        String body = "{ user { name } }";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String decoded = codec.decode(orig);
        // For raw-query bodies, decode produces only the [query] block (no envelope).
        assertTrue(decoded.contains("[query]"));
        assertFalse(decoded.contains("[variables]"));
        byte[] reEncoded = codec.encode(decoded, orig);
        String back = new String(reEncoded, StandardCharsets.UTF_8);
        assertTrue(back.contains("user"), back);
    }

    @Test
    void encodeRefusesErrorPlaceholder() {
        assertThrows(RuntimeException.class,
                () -> codec.encode("/* COMINT GraphQL decode error */"));
        assertThrows(RuntimeException.class,
                () -> codec.encode("/* COMINT GraphQL decode error */", new byte[0]));
    }

    @Test
    void rejectsLargePayload() {
        byte[] huge = new byte[33 * 1024 * 1024];
        String result = codec.decode(huge);
        assertTrue(result.startsWith("/* COMINT GraphQL"), "got: " + result);
    }

    @Test
    void malformedQueryEncodesVerbatim() throws Exception {
        // User mid-edit: typed broken GraphQL. Codec must not block fuzzing.
        String body = "{\"query\":\"{ valid }\"}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String brokenEdit = "[query]\n{ this is not valid {{\n";
        byte[] reEncoded = codec.encode(brokenEdit, orig);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertTrue(reParsed.get("query").asText().contains("not valid"));
    }

    @Test
    void encodeWithNullOriginalProducesValidJsonEnvelope() throws Exception {
        String userEdit = "[query]\n{ ping }\n\n[variables]\n{\"x\":1}\n[operationName]\nPing\n";
        byte[] reEncoded = codec.encode(userEdit, null);
        JsonNode reParsed = mapper.readTree(reEncoded);
        assertEquals("Ping", reParsed.get("operationName").asText());
        assertEquals(1, reParsed.get("variables").get("x").asInt());
        assertTrue(reParsed.get("query").asText().contains("ping"));
    }

    @Test
    void roundTripDecodeIsStable() {
        // decode(encode(decoded, original)) MUST equal decoded — block format must round-trip.
        String body = "{\"query\":\"query GetUser($id: ID!) { user(id: $id) { name } }\"," +
                "\"variables\":{\"id\":\"42\"}," +
                "\"operationName\":\"GetUser\"}";
        byte[] orig = body.getBytes(StandardCharsets.UTF_8);
        String first = codec.decode(orig);
        byte[] reEncoded = codec.encode(first, orig);
        String second = codec.decode(reEncoded);
        assertEquals(first, second);
    }
}
