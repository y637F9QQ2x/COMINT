package com.comint.ui;

import javax.swing.table.AbstractTableModel;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Backing model for the COMINT Traffic JTable. EDT-only — all mutation methods
 * must be called on the EDT (the panel uses {@code SwingUtilities.invokeLater}).
 */
public class ComintTrafficTableModel extends AbstractTableModel {

    /** R26: storage cap. Entries hold lazy references (HttpRequest/HttpResponse — Burp
     *  manages the backing memory) plus only the raw WS payload bytes/string for
     *  message frames; decoded JSON is computed on demand by the panel. */
    public static final int CAP = 100000;

    private static final String[] COLS = {
            "No.", "Timestamp", "Host", "Method", "Source", "URL", "Protocol", "Codec", "Status", "Length"
    };

    private final List<ComintTrafficEntry> entries = new ArrayList<>();
    // R19: yyyy-MM-dd HH:mm:ss.SSS with Locale.ROOT to keep formatting identical
    // regardless of the JVM's default locale (some locales reorder day/month).
    // Audit fix: DateTimeFormatter is immutable + thread-safe (SimpleDateFormat
    // wasn't, even though we're EDT-only by convention).
    private static final DateTimeFormatter TS_FMT = DateTimeFormatter
            .ofPattern("yyyy-MM-dd HH:mm:ss.SSS", Locale.ROOT)
            .withZone(ZoneId.systemDefault());

    public void addEntry(ComintTrafficEntry entry) {
        if (entry == null) return;
        if (entries.size() >= CAP) {
            entries.remove(0);
            fireTableRowsDeleted(0, 0);
        }
        entries.add(entry);
        int row = entries.size() - 1;
        fireTableRowsInserted(row, row);
    }

    public ComintTrafficEntry getEntry(int row) {
        if (row < 0 || row >= entries.size()) return null;
        return entries.get(row);
    }

    public void clear() {
        int n = entries.size();
        if (n == 0) return;
        entries.clear();
        fireTableRowsDeleted(0, n - 1);
    }

    /** Toggle (or set) the hidden flag on the entry at this model row. */
    public void setHidden(int modelRow, boolean hidden) {
        ComintTrafficEntry e = getEntry(modelRow);
        if (e == null) return;
        e.setHidden(hidden);
        fireTableRowsUpdated(modelRow, modelRow);
    }

    @Override
    public int getRowCount() {
        return entries.size();
    }

    @Override
    public int getColumnCount() {
        return COLS.length;
    }

    @Override
    public String getColumnName(int col) {
        return (col >= 0 && col < COLS.length) ? COLS[col] : "";
    }

    @Override
    public Class<?> getColumnClass(int col) {
        // No (0), Status (8), Length (9) — Integer; everything else String.
        return switch (col) {
            case 0, 8, 9 -> Integer.class;
            default -> String.class;
        };
    }

    @Override
    public boolean isCellEditable(int row, int col) {
        return false;
    }

    @Override
    public Object getValueAt(int row, int col) {
        ComintTrafficEntry e = getEntry(row);
        if (e == null) return "";
        return switch (col) {
            case 0 -> Integer.valueOf(e.id);
            case 1 -> TS_FMT.format(Instant.ofEpochMilli(e.timestamp));
            case 2 -> e.host;
            case 3 -> e.method;
            case 4 -> e.source;
            case 5 -> e.url;
            case 6 -> e.protocol;
            case 7 -> e.codec;
            case 8 -> Integer.valueOf(e.statusCode);
            case 9 -> Integer.valueOf(e.length);
            default -> "";
        };
    }
}
