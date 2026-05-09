package com.comint.ui;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ComintTrafficTableModelTest {

    @Test
    void columnHeadersMatchSpec() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        assertEquals(9, m.getColumnCount());
        assertEquals("No.", m.getColumnName(0));
        assertEquals("Timestamp", m.getColumnName(1));
        assertEquals("Host", m.getColumnName(2));
        assertEquals("Method", m.getColumnName(3));
        assertEquals("URL", m.getColumnName(4));
        assertEquals("Protocol", m.getColumnName(5));
        assertEquals("Codec", m.getColumnName(6));
        assertEquals("Status", m.getColumnName(7));
        assertEquals("Length", m.getColumnName(8));
    }

    @Test
    void addEntryAppendsAndIsRetrievable() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        ComintTrafficEntry e = ComintTrafficEntry.builder()
                .id(1).host("example.com").method("GET").url("https://example.com/api")
                .protocol("HTTPS").codec("Protobuf").statusCode(200).reason("OK").length(123)
                .build();
        m.addEntry(e);
        assertEquals(1, m.getRowCount());
        assertEquals("example.com", m.getValueAt(0, 2));
        assertEquals("GET", m.getValueAt(0, 3));
        assertEquals("Protobuf", m.getValueAt(0, 6));
        assertEquals(Integer.valueOf(200), m.getValueAt(0, 7));
    }

    @Test
    void capEvictsOldestEntry() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        for (int i = 0; i < ComintTrafficTableModel.CAP + 5; i++) {
            m.addEntry(ComintTrafficEntry.builder().id(i).method("GET").build());
        }
        assertEquals(ComintTrafficTableModel.CAP, m.getRowCount());
        // Oldest row's id should now be at least 5 (we inserted 0..CAP+4 and dropped 5).
        Object oldest = m.getValueAt(0, 0);
        assertTrue(oldest instanceof Integer);
        assertEquals(5, ((Integer) oldest).intValue());
    }

    @Test
    void clearEmptiesModel() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        m.addEntry(ComintTrafficEntry.builder().id(1).method("GET").build());
        m.addEntry(ComintTrafficEntry.builder().id(2).method("POST").build());
        assertEquals(2, m.getRowCount());
        m.clear();
        assertEquals(0, m.getRowCount());
    }

    @Test
    void getValueAtOutOfBoundsReturnsEmpty() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        assertEquals("", m.getValueAt(99, 0));
    }

    @Test
    void getEntryOutOfBoundsReturnsNull() {
        ComintTrafficTableModel m = new ComintTrafficTableModel();
        assertNull(m.getEntry(0));
        assertNull(m.getEntry(-1));
    }
}
