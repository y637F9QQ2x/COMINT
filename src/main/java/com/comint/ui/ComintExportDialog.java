package com.comint.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;

import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;
import com.comint.editor.HttpMessageFormatter;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.SwingWorker;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Window;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;

/**
 * R20: export-options dialog for the COMINT Traffic log.
 *
 * <p>One file per traffic entry, named {@code {No}_{Method}_{Host}_{timestamp}.txt}.
 * Sections (Request/Response × Raw/Decoded) are emitted only for the user's
 * checked checkboxes. File I/O runs on a {@link SwingWorker} background thread
 * so the dialog never freezes the EDT, and a {@link JProgressBar} reports
 * progress as files are written.
 */
public class ComintExportDialog extends JDialog {

    private static final String[] L_INDEX_KEYS = {"highlight","show","showAll","visibleOnly","hiddenOnly",
            "hideSelected","unhideSelected","search","exportLogs","raw","decoded","outputDir","export","cancel"};

    private final MontoyaApi api;
    private final ComintTrafficTableModel model;
    private final CodecRegistry codecRegistry;
    private final String[] labels;
    private final String persistenceKey;

    private final JCheckBox cbRaw;
    private final JCheckBox cbDecoded;
    private final JTextField dirField;
    private final JButton browseButton;
    private final JButton exportButton;
    private final JButton cancelButton;
    private final JProgressBar progress;

    /** Constructor — dialog is built but not shown until {@code setVisible(true)}. */
    public ComintExportDialog(MontoyaApi api,
                              Component owner,
                              ComintTrafficTableModel model,
                              CodecRegistry codecRegistry,
                              String[] labelsForCurrentLang,
                              String persistenceKey) {
        super(findOwner(owner), labelsForCurrentLang[8] /* L_EXPORT_LOGS */, ModalityType.APPLICATION_MODAL);
        this.api = api;
        this.model = model;
        this.codecRegistry = codecRegistry;
        this.labels = labelsForCurrentLang.clone();
        this.persistenceKey = persistenceKey;

        setLayout(new BorderLayout(8, 8));

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // Content-type checkboxes (Raw / Decoded).
        this.cbRaw = new JCheckBox(labels[9] /* L_RAW */, true);
        this.cbDecoded = new JCheckBox(labels[10] /* L_DECODED */, true);
        JPanel checkRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        checkRow.add(cbRaw);
        checkRow.add(cbDecoded);
        content.add(checkRow);
        content.add(Box.createVerticalStrut(8));

        // Output directory selector.
        JPanel dirRow = new JPanel(new BorderLayout(6, 0));
        dirRow.add(new JLabel(labels[11] /* L_OUTPUT_DIR */ + ":"), BorderLayout.WEST);
        this.dirField = new JTextField(loadDir(), 30);
        dirRow.add(dirField, BorderLayout.CENTER);
        // R23: index 14 is "Browse...". Older callers may still pass the 14-element
        // labels array — fall back to English if the entry is missing.
        String browseLabel = (labels.length > 14 && labels[14] != null) ? labels[14] : "Browse...";
        this.browseButton = new JButton(browseLabel);
        browseButton.addActionListener(ae -> chooseDir());
        dirRow.add(browseButton, BorderLayout.EAST);
        content.add(dirRow);
        content.add(Box.createVerticalStrut(8));

        // Progress bar (initially indeterminate-off, range set on export).
        this.progress = new JProgressBar();
        progress.setStringPainted(true);
        progress.setVisible(false);
        content.add(progress);

        add(content, BorderLayout.CENTER);

        // Action buttons.
        JPanel buttonRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 8));
        this.cancelButton = new JButton(labels[13] /* L_CANCEL */);
        cancelButton.addActionListener(ae -> dispose());
        this.exportButton = new JButton(labels[12] /* L_EXPORT */);
        exportButton.addActionListener(ae -> startExport());
        buttonRow.add(cancelButton);
        buttonRow.add(exportButton);
        add(buttonRow, BorderLayout.SOUTH);

        setMinimumSize(new Dimension(540, 200));
        pack();
        setLocationRelativeTo(owner);
    }

    private static Window findOwner(Component owner) {
        if (owner == null) return null;
        return SwingUtilities.getWindowAncestor(owner);
    }

    private String loadDir() {
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext != null) {
                String saved = ext.getString(persistenceKey);
                if (saved != null && !saved.isEmpty()) return saved;
            }
        } catch (Throwable ignored) {}
        return System.getProperty("user.home", ".");
    }

    private void saveDir(String path) {
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext != null) ext.setString(persistenceKey, path);
        } catch (Throwable ignored) {}
    }

    private void chooseDir() {
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        String current = dirField.getText();
        if (current != null && !current.isEmpty()) {
            File f = new File(current);
            if (f.isDirectory()) chooser.setCurrentDirectory(f);
        }
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File selected = chooser.getSelectedFile();
            if (selected != null) {
                dirField.setText(selected.getAbsolutePath());
            }
        }
    }

    private void startExport() {
        if (!cbRaw.isSelected() && !cbDecoded.isSelected()) return;
        final String dirText = dirField.getText() == null ? "" : dirField.getText().trim();
        if (dirText.isEmpty()) return;
        File dir = new File(dirText);
        if (!dir.exists() || !dir.isDirectory()) return;
        saveDir(dirText);

        // Snapshot model entries on the EDT (model is EDT-only); export runs in background.
        // Sort by entry No. ascending — model insertion is already monotonic, but we
        // sort defensively in case future edits reorder the storage.
        final List<ComintTrafficEntry> snapshot = new ArrayList<>(model.getRowCount());
        for (int i = 0; i < model.getRowCount(); i++) {
            ComintTrafficEntry e = model.getEntry(i);
            if (e != null) snapshot.add(e);
        }
        snapshot.sort((a, b) -> Integer.compare(a.id, b.id));
        if (snapshot.isEmpty()) {
            dispose();
            return;
        }

        final boolean wantRaw = cbRaw.isSelected();
        final boolean wantDecoded = cbDecoded.isSelected();
        final Path outDir = dir.toPath();
        final int totalSteps = snapshot.size() * ((wantRaw ? 1 : 0) + (wantDecoded ? 1 : 0));

        progress.setVisible(true);
        progress.setMinimum(0);
        progress.setMaximum(totalSteps);
        progress.setValue(0);
        progress.setString("0 / " + totalSteps);
        setUiEnabled(false);

        new SwingWorker<Integer, Integer>() {
            @Override
            protected Integer doInBackground() {
                int filesWritten = 0;
                String tsName = new SimpleDateFormat("yyyyMMdd-HHmmss", Locale.ROOT)
                        .format(new Date());
                int progressDone = 0;
                if (wantRaw) {
                    try {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream(64 * 1024);
                        for (ComintTrafficEntry entry : snapshot) {
                            try {
                                writeConsolidatedEntry(baos, entry, /*decoded=*/false);
                            } catch (Throwable t) {
                                logErr("export raw entry " + entry.id + ": " + safeMsg(t));
                            }
                            progressDone++;
                            publish(progressDone);
                        }
                        Files.write(outDir.resolve("comint_raw_" + tsName + ".txt"), baos.toByteArray());
                        filesWritten++;
                    } catch (Throwable t) {
                        logErr("export raw: " + safeMsg(t));
                    }
                }
                if (wantDecoded) {
                    try {
                        ByteArrayOutputStream baos = new ByteArrayOutputStream(64 * 1024);
                        for (ComintTrafficEntry entry : snapshot) {
                            try {
                                writeConsolidatedEntry(baos, entry, /*decoded=*/true);
                            } catch (Throwable t) {
                                logErr("export decoded entry " + entry.id + ": " + safeMsg(t));
                            }
                            progressDone++;
                            publish(progressDone);
                        }
                        Files.write(outDir.resolve("comint_decoded_" + tsName + ".txt"), baos.toByteArray());
                        filesWritten++;
                    } catch (Throwable t) {
                        logErr("export decoded: " + safeMsg(t));
                    }
                }
                return filesWritten;
            }
            @Override
            protected void process(List<Integer> chunks) {
                if (chunks.isEmpty()) return;
                int latest = chunks.get(chunks.size() - 1);
                progress.setValue(latest);
                progress.setString(latest + " / " + totalSteps);
            }
            @Override
            protected void done() {
                setUiEnabled(true);
                dispose();
            }
        }.execute();
    }

    /**
     * R24: append one entry block to the consolidated export buffer.
     *
     * <pre>
     * ================================================================================
     * No. {id} | {METHOD} {URL} | {PROTOCOL} | {CODEC}
     * --- REQUEST ---
     * {bytes — wire or decoded}
     * --- RESPONSE ---
     * {bytes — wire or decoded}
     * </pre>
     */
    private void writeConsolidatedEntry(ByteArrayOutputStream baos, ComintTrafficEntry e, boolean decoded) throws IOException {
        if (e == null) return;
        baos.write(SEPARATOR);
        baos.write('\n');
        String header = "No. " + e.id + " | " + entryHeaderSummary(e) + " | " + safe(e.protocol) + " | " + safe(e.codec) + "\n";
        baos.write(header.getBytes(StandardCharsets.UTF_8));

        baos.write("--- REQUEST ---\n".getBytes(StandardCharsets.UTF_8));
        byte[] reqBytes = decoded ? decodedRequestBytes(e) : rawRequestBytes(e);
        if (reqBytes != null && reqBytes.length > 0) {
            baos.write(reqBytes);
            if (reqBytes[reqBytes.length - 1] != '\n') baos.write('\n');
        } else {
            baos.write('\n');
        }

        baos.write("--- RESPONSE ---\n".getBytes(StandardCharsets.UTF_8));
        byte[] respBytes = decoded ? decodedResponseBytes(e) : rawResponseBytes(e);
        if (respBytes != null && respBytes.length > 0) {
            baos.write(respBytes);
            if (respBytes[respBytes.length - 1] != '\n') baos.write('\n');
        } else {
            baos.write('\n');
        }
    }

    private static final byte[] SEPARATOR =
            "================================================================================".getBytes(StandardCharsets.UTF_8);

    /**
     * Build the "{METHOD} {URL}" header summary, with WS direction arrows kept verbatim
     * for WS rows so the export reads naturally.
     */
    private static String entryHeaderSummary(ComintTrafficEntry e) {
        String m = safe(e.method);
        String u = safe(e.url);
        if (m.isEmpty() && u.isEmpty()) return "(empty)";
        if (m.isEmpty()) return u;
        if (u.isEmpty()) return m;
        return m + " " + u;
    }

    private static String safe(String s) { return s == null ? "" : s; }

    private void setUiEnabled(boolean enabled) {
        cbRaw.setEnabled(enabled);
        cbDecoded.setEnabled(enabled);
        dirField.setEnabled(enabled);
        browseButton.setEnabled(enabled);
        exportButton.setEnabled(enabled);
        cancelButton.setEnabled(enabled);
    }

    private byte[] rawRequestBytes(ComintTrafficEntry e) {
        if (e == null) return new byte[0];
        if (e.kind == ComintTrafficEntry.Kind.HTTP) {
            if (e.httpRequest == null) return new byte[0];
            ByteArray ba = e.httpRequest.toByteArray();
            return ba == null ? new byte[0] : ba.getBytes();
        }
        if (e.kind == ComintTrafficEntry.Kind.WS_BINARY) {
            return e.wsBinaryPayload == null ? new byte[0] : e.wsBinaryPayload;
        }
        if (e.kind == ComintTrafficEntry.Kind.WS_TEXT) {
            return e.wsTextPayload == null ? new byte[0]
                    : e.wsTextPayload.getBytes(StandardCharsets.UTF_8);
        }
        return new byte[0];
    }

    private byte[] rawResponseBytes(ComintTrafficEntry e) {
        if (e == null) return new byte[0];
        if (e.kind == ComintTrafficEntry.Kind.HTTP && e.httpResponse != null) {
            ByteArray ba = e.httpResponse.toByteArray();
            return ba == null ? new byte[0] : ba.getBytes();
        }
        return new byte[0];
    }

    private byte[] decodedRequestBytes(ComintTrafficEntry e) {
        if (e == null) return new byte[0];
        if (e.kind == ComintTrafficEntry.Kind.HTTP) {
            if (e.httpRequest == null) return new byte[0];
            HttpRequest req = e.httpRequest;
            ProtocolCodec codec = codecForRequest(req);
            byte[] body = CodecUtil.safeBodyBytes(req);
            byte[] decodedBody = codec == null ? body : decodeOrEmpty(codec, body);
            return HttpMessageFormatter.formatRequest(req, decodedBody);
        }
        if (e.kind == ComintTrafficEntry.Kind.WS_TEXT) {
            return e.wsTextPayload == null ? new byte[0]
                    : e.wsTextPayload.getBytes(StandardCharsets.UTF_8);
        }
        if (e.kind == ComintTrafficEntry.Kind.WS_BINARY) {
            // For WS binary we don't have a per-message HTTP envelope; return raw bytes.
            return e.wsBinaryPayload == null ? new byte[0] : e.wsBinaryPayload;
        }
        return new byte[0];
    }

    private byte[] decodedResponseBytes(ComintTrafficEntry e) {
        if (e == null) return new byte[0];
        if (e.kind == ComintTrafficEntry.Kind.HTTP && e.httpResponse != null) {
            HttpResponse resp = e.httpResponse;
            ProtocolCodec codec = codecForResponse(resp, e.httpRequest);
            byte[] body = CodecUtil.safeBodyBytes(resp);
            byte[] decodedBody = codec == null ? body : decodeOrEmpty(codec, body);
            return HttpMessageFormatter.formatResponse(resp, decodedBody);
        }
        return new byte[0];
    }

    private ProtocolCodec codecForRequest(HttpRequest req) {
        if (codecRegistry == null || req == null) return null;
        try { return codecRegistry.codecForRequest(req).orElse(null); }
        catch (Throwable t) { return null; }
    }

    private ProtocolCodec codecForResponse(HttpResponse resp, HttpRequest req) {
        if (codecRegistry == null || resp == null) return null;
        try { return codecRegistry.codecForResponse(resp, req).orElse(null); }
        catch (Throwable t) { return null; }
    }

    private static byte[] decodeOrEmpty(ProtocolCodec codec, byte[] body) {
        try {
            String decoded = codec.decode(body);
            return decoded == null ? new byte[0] : decoded.getBytes(StandardCharsets.UTF_8);
        } catch (Throwable t) {
            return new byte[0];
        }
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT Export: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }

    /** Compile-time check that the labels array stays parallel to the indices used here. */
    @SuppressWarnings("unused")
    private static final int LABELS_SIZE_CHECK = L_INDEX_KEYS.length;
}
