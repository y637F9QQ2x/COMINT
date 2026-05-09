package com.comint.scanner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ComintJsonInsertionPointTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void replaceAtPointerAtObjectLeaf() throws Exception {
        JsonNode root = mapper.readTree("{\"a\":\"orig\",\"b\":1}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/a", "PAYLOAD");
        assertEquals("PAYLOAD", root.get("a").asText());
        assertEquals(1, root.get("b").asInt());
    }

    @Test
    void replaceAtPointerNested() throws Exception {
        JsonNode root = mapper.readTree("{\"x\":{\"y\":\"orig\"}}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/x/y", "PAYLOAD");
        assertEquals("PAYLOAD", root.get("x").get("y").asText());
    }

    @Test
    void replaceAtPointerArrayElement() throws Exception {
        JsonNode root = mapper.readTree("{\"arr\":[\"a\",\"b\",\"c\"]}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/arr/1", "PAYLOAD");
        assertEquals("PAYLOAD", root.get("arr").get(1).asText());
    }

    @Test
    void replaceAtPointerProtobufShape() throws Exception {
        // Protobuf's decoded shape: {"1": [{"type":"string","value":"orig"}]}
        JsonNode root = mapper.readTree("{\"1\":[{\"type\":\"string\",\"value\":\"orig\"}]}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/1/0/value", "PAYLOAD");
        assertEquals("PAYLOAD", root.get("1").get(0).get("value").asText());
        // The 'type' tag must be untouched.
        assertEquals("string", root.get("1").get(0).get("type").asText());
    }

    @Test
    void walkStringLeavesFindsLeafsRecursively() throws Exception {
        JsonNode root = mapper.readTree("{\"a\":\"x\",\"b\":{\"c\":\"y\"},\"d\":[\"z\",1]}");
        List<String> pointers = new ArrayList<>();
        ComintInsertionPointProvider.walkStringLeaves(root, "", pointers, false);
        assertTrue(pointers.contains("/a"));
        assertTrue(pointers.contains("/b/c"));
        assertTrue(pointers.contains("/d/0"));
        assertFalse(pointers.contains("/d/1"), "numeric leaf must not be included");
    }

    @Test
    void walkStringLeavesSkipsProtobufTypeTags() throws Exception {
        // For protobuf-shaped trees, the "type" key is metadata and must not become an insertion point.
        JsonNode root = mapper.readTree("{\"1\":[{\"type\":\"string\",\"value\":\"hello\"}]}");
        List<String> pointers = new ArrayList<>();
        ComintInsertionPointProvider.walkStringLeaves(root, "", pointers, true);
        assertFalse(pointers.contains("/1/0/type"), "protobuf 'type' must be skipped: " + pointers);
        assertTrue(pointers.contains("/1/0/value"));
    }

    @Test
    void replaceAtPointerEscaped() throws Exception {
        // RFC 6901: "/" inside a key is encoded as "~1" inside the pointer.
        JsonNode root = mapper.readTree("{\"a/b\":\"orig\"}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/a~1b", "PAYLOAD");
        assertEquals("PAYLOAD", root.get("a/b").asText());
    }

    @Test
    void replaceAtPointerLeavesUnrelatedKeysAlone() throws Exception {
        // R16 active-scan path hands the provider a JSON-body request (already decoded);
        // replace must edit only the targeted leaf and preserve siblings.
        JsonNode root = mapper.readTree("{\"a\":\"x\",\"b\":{\"c\":\"y\",\"d\":\"z\"}}");
        ComintJsonInsertionPoint.replaceAtPointer(root, "/b/c", "PAYLOAD");
        assertEquals("x", root.get("a").asText());
        assertEquals("PAYLOAD", root.get("b").get("c").asText());
        assertEquals("z", root.get("b").get("d").asText());
    }
}
