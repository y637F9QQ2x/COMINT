package com.comint.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.ui.Theme;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.RawEditor;

import com.comint.bridge.ComintWsBridge;
import com.comint.codec.CodecRegistry;
import com.comint.codec.CodecUtil;
import com.comint.codec.ProtocolCodec;
import com.comint.editor.HttpMessageFormatter;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.nio.charset.StandardCharsets;
import java.util.Comparator;

public class ComintTrafficPanel extends JPanel implements ComintTrafficListener {

    private static final String CARD_HTTP = "http";
    private static final String CARD_EMPTY = "empty";

    private static final int COL_NO = 0;
    private static final int COL_TIMESTAMP = 1;
    private static final int COL_HOST = 2;
    private static final int COL_METHOD = 3;
    private static final int COL_SOURCE = 4;
    private static final int COL_URL = 5;
    private static final int COL_PROTOCOL = 6;
    private static final int COL_CODEC = 7;
    private static final int COL_STATUS = 8;
    private static final int COL_LENGTH = 9;

    private static final String PERSISTENCE_LANG_KEY = "comint.lang";

    private static final String[] LANG_CODES = {"en", "ja", "ko", "zh-CN", "zh-TW", "ru"};
    private static final String[] LANG_LABELS = {"English", "日本語", "한국어", "简体中文", "繁體中文", "Русский"};
    private static final String[][] HEADERS = {
            // English
            {"No.", "Timestamp", "Host", "Method", "Source", "URL", "Protocol", "Codec", "Status", "Length"},
            // Japanese
            {"No.", "タイムスタンプ", "ホスト", "メソッド", "発信元", "URL", "プロトコル", "コーデック", "ステータス", "サイズ"},
            // Korean
            {"No.", "타임스탬프", "호스트", "메서드", "발신원", "URL", "프로토콜", "코덱", "상태", "크기"},
            // Simplified Chinese
            {"No.", "时间戳", "主机", "方法", "来源", "URL", "协议", "编解码器", "状态", "大小"},
            // Traditional Chinese
            {"No.", "時間戳", "主機", "方法", "來源", "URL", "協議", "編解碼器", "狀態", "大小"},
            // Russian
            {"No.", "Метка времени", "Хост", "Метод", "Источник", "URL", "Протокол", "Кодек", "Статус", "Размер"},
    };

    // R17: translations for COMINT-original UI strings, parallel to LANG_CODES.
    private static final int L_HIGHLIGHT       = 0;
    private static final int L_SHOW            = 1;
    private static final int L_SHOW_ALL        = 2;
    private static final int L_VISIBLE_ONLY    = 3;
    private static final int L_HIDDEN_ONLY     = 4;
    private static final int L_HIDE_SELECTED   = 5;
    private static final int L_UNHIDE_SELECTED = 6;
    private static final int L_SEARCH          = 7;
    private static final int L_EXPORT_LOGS     = 8;
    private static final int L_RAW             = 9;
    private static final int L_DECODED         = 10;
    private static final int L_OUTPUT_DIR      = 11;
    private static final int L_EXPORT          = 12;
    private static final int L_CANCEL          = 13;
    private static final int L_BROWSE          = 14;
    private static final int L_STATUS_PATTERN  = 15;
    private static final int L_WS_BRIDGE       = 16;
    private static final int L_START           = 17;
    private static final int L_STOP            = 18;
    private static final String[][] LABELS = {
            // English
            {"Highlight:", "Show:", "Show all", "Visible only", "Hidden only",
             "Hide selected", "Unhide selected", "Search...", "Export Logs",
             "Raw (before decode)", "Decoded (after decode)",
             "Output directory", "Export", "Cancel",
             "Browse...",
             "COMINT Traffic — capturing {0} entries (cap {1})",
             "WS Bridge:", "Start", "Stop"},
            // Japanese
            {"ハイライト:", "表示:", "すべて表示", "表示のみ", "非表示のみ",
             "選択を非表示", "選択を再表示", "検索...", "ログ出力",
             "デコード前", "デコード後",
             "出力先", "エクスポート", "キャンセル",
             "参照...",
             "COMINT Traffic — {0} 件キャプチャ中（上限 {1}）",
             "WS ブリッジ:", "開始", "停止"},
            // Korean
            {"하이라이트:", "표시:", "모두 표시", "표시만", "숨김만",
             "선택 숨기기", "선택 표시", "검색...", "로그 출력",
             "디코딩 전", "디코딩 후",
             "출력 경로", "내보내기", "취소",
             "찾아보기...",
             "COMINT Traffic — {0}건 캡처 중 (최대 {1})",
             "WS 브리지:", "시작", "중지"},
            // Simplified Chinese
            {"高亮:", "显示:", "显示全部", "仅可见", "仅隐藏",
             "隐藏所选", "取消隐藏", "搜索...", "导出日志",
             "解码前", "解码后",
             "输出目录", "导出", "取消",
             "浏览...",
             "COMINT Traffic — 正在捕获 {0} 条记录（上限 {1}）",
             "WS 桥接:", "启动", "停止"},
            // Traditional Chinese
            {"高亮:", "顯示:", "顯示全部", "僅可見", "僅隱藏",
             "隱藏所選", "取消隱藏", "搜尋...", "匯出日誌",
             "解碼前", "解碼後",
             "輸出目錄", "匯出", "取消",
             "瀏覽...",
             "COMINT Traffic — 正在擷取 {0} 筆記錄（上限 {1}）",
             "WS 橋接:", "啟動", "停止"},
            // Russian
            {"Подсветка:", "Показать:", "Показать все", "Только видимые", "Только скрытые",
             "Скрыть выбранные", "Показать выбранные", "Поиск...", "Экспорт логов",
             "До декодирования", "После декодирования",
             "Директория вывода", "Экспорт", "Отмена",
             "Обзор...",
             "COMINT Traffic — захвачено {0} записей (лимит {1})",
             "WS Bridge:", "Запуск", "Остановка"},
    };

    private final MontoyaApi api;
    private final CodecRegistry codecRegistry;
    private final ComintTrafficTableModel model;
    private final JTable table;
    private final TableRowSorter<ComintTrafficTableModel> sorter;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final JPanel detailCardPanel;
    private final CardLayout detailCardLayout;
    private final JSplitPane httpSplit;
    private final JLabel statusLabel;

    private final JCheckBox cbProtobuf;
    private final JCheckBox cbGrpcWeb;
    private final JCheckBox cbMsgPack;
    private final JCheckBox cbGraphQL;
    private final JCheckBox cbWebSocket;

    private final JRadioButton rbShowAll;
    private final JRadioButton rbVisibleOnly;
    private final JRadioButton rbHiddenOnly;

    private final JComboBox<String> langCombo;

    // R17: translatable UI components — text is updated by applyLanguage().
    private final JLabel highlightLabel = new JLabel();
    private final JLabel showLabel = new JLabel();
    private JMenuItem hideMenuItem;
    private JMenuItem unhideMenuItem;
    // R18 / R20:
    private JTextField searchField;
    private JButton exportButton;
    // R20: persisted last-used directory key.
    private static final String PERSISTENCE_EXPORT_DIR_KEY = "comint.exportDir";

    // WS-4 (revised): inline bridge controls live in the top-right toolbar.
    private final ComintWsBridge wsBridge;
    private JLabel bridgeLabel;
    private JTextField bridgePortField;
    private JButton bridgeToggleButton;
    private JLabel bridgeStatusDot;
    private javax.swing.Timer bridgeStatusTimer;

    // Holder panels for the JSplitPane sides — they wrap the request/response editors
    // so the underlying split pane has stable children even though contents may change.
    private JPanel leftDetailHolder;
    private JPanel rightDetailHolder;

    private int currentLangIdx = 0;

    private final Color colorProtobuf;
    private final Color colorGrpcWeb;
    private final Color colorMsgPack;
    private final Color colorGraphQL;
    private final Color colorWebSocket;

    public ComintTrafficPanel(MontoyaApi api, CodecRegistry codecRegistry) {
        this(api, codecRegistry, null);
    }

    public ComintTrafficPanel(MontoyaApi api, CodecRegistry codecRegistry, ComintWsBridge wsBridge) {
        this.api = api;
        this.codecRegistry = codecRegistry;
        this.wsBridge = wsBridge;
        this.model = new ComintTrafficTableModel();

        boolean dark = false;
        try {
            Theme t = api.userInterface().currentTheme();
            dark = t == Theme.DARK;
        } catch (Throwable ignored) {}

        if (dark) {
            this.colorProtobuf = new Color(0x1E3A5F);
            this.colorGrpcWeb = new Color(0x14532D);
            this.colorMsgPack = new Color(0x713F12);
            this.colorGraphQL = new Color(0x581C87);
            this.colorWebSocket = new Color(0x7C2D12);
        } else {
            this.colorProtobuf = new Color(0xDBEAFE);
            this.colorGrpcWeb = new Color(0xDCFCE7);
            this.colorMsgPack = new Color(0xFEF9C3);
            this.colorGraphQL = new Color(0xF3E8FF);
            this.colorWebSocket = new Color(0xFFEDD5);
        }

        setLayout(new BorderLayout());

        // ---- Top toolbar: highlight row + visibility row, with language switcher right-aligned ----
        JPanel topToolbar = new JPanel(new BorderLayout());

        JPanel highlightRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        highlightLabel.setText("Highlight:");
        highlightRow.add(highlightLabel);
        this.cbProtobuf = new JCheckBox("Protobuf");
        this.cbGrpcWeb = new JCheckBox("gRPC-Web");
        this.cbMsgPack = new JCheckBox("MessagePack");
        this.cbGraphQL = new JCheckBox("GraphQL");
        this.cbWebSocket = new JCheckBox("WebSocket");
        highlightRow.add(cbProtobuf);
        highlightRow.add(cbGrpcWeb);
        highlightRow.add(cbMsgPack);
        highlightRow.add(cbGraphQL);
        highlightRow.add(cbWebSocket);

        // Visibility filter row (R13).
        JPanel visibilityRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        showLabel.setText("Show:");
        visibilityRow.add(showLabel);
        this.rbShowAll = new JRadioButton("Show all", true);
        this.rbVisibleOnly = new JRadioButton("Visible only");
        this.rbHiddenOnly = new JRadioButton("Hidden only");
        ButtonGroup visibilityGroup = new ButtonGroup();
        visibilityGroup.add(rbShowAll);
        visibilityGroup.add(rbVisibleOnly);
        visibilityGroup.add(rbHiddenOnly);
        visibilityRow.add(rbShowAll);
        visibilityRow.add(rbVisibleOnly);
        visibilityRow.add(rbHiddenOnly);

        JPanel rowsStack = new JPanel();
        rowsStack.setLayout(new BoxLayout(rowsStack, BoxLayout.Y_AXIS));
        rowsStack.add(highlightRow);
        rowsStack.add(visibilityRow);
        topToolbar.add(rowsStack, BorderLayout.CENTER);

        // Top-right cluster: search field (R18), Export Logs (R20), language switcher (R15).
        JPanel rightWrap = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 4));

        PlaceholderField search = new PlaceholderField(18);
        search.setPlaceholder("Search...");
        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });
        this.searchField = search;
        rightWrap.add(search);

        this.exportButton = new JButton("Export Logs");
        exportButton.addActionListener(ae -> openExportDialog());
        rightWrap.add(exportButton);

        this.langCombo = new JComboBox<>(LANG_LABELS);
        langCombo.setMaximumRowCount(LANG_LABELS.length);
        rightWrap.add(langCombo);

        // WS-4 (revised): inline Bridge controls. Compact row that lives in the same
        // top-right cluster as Search / Export / Language. The standalone "COMINT WS
        // Bridge" suite tab is gone — these controls replace it.
        if (wsBridge != null) {
            rightWrap.add(Box.createHorizontalStrut(8));
            this.bridgeLabel = new JLabel("WS Bridge:");
            rightWrap.add(bridgeLabel);
            this.bridgePortField = new JTextField(Integer.toString(wsBridge.port()), 5);
            rightWrap.add(bridgePortField);
            this.bridgeToggleButton = new JButton(wsBridge.isRunning() ? "Stop" : "Start");
            bridgeToggleButton.addActionListener(ae -> toggleBridge());
            rightWrap.add(bridgeToggleButton);
            this.bridgeStatusDot = new JLabel("●"); // ●
            bridgeStatusDot.setForeground(wsBridge.isRunning() ? new Color(0x22C55E) : new Color(0xEF4444));
            bridgeStatusDot.setToolTipText(wsBridge.isRunning() ? "Bridge running" : "Bridge stopped");
            rightWrap.add(bridgeStatusDot);

            // Refresh state every 1.5s (the bridge can be stopped/started elsewhere).
            this.bridgeStatusTimer = new javax.swing.Timer(1500, ae -> refreshBridgeStatus());
            bridgeStatusTimer.start();
        }

        topToolbar.add(rightWrap, BorderLayout.EAST);

        add(topToolbar, BorderLayout.NORTH);

        // ---- Table ----
        this.table = new JTable(model) {
            @Override
            public Component prepareRenderer(TableCellRenderer renderer, int row, int col) {
                Component c = super.prepareRenderer(renderer, row, col);
                if (isRowSelected(row)) {
                    c.setBackground(getSelectionBackground());
                    c.setForeground(getSelectionForeground());
                } else {
                    Color bg = backgroundForRow(row);
                    c.setBackground(bg != null ? bg : getBackground());
                    c.setForeground(getForeground());
                }
                return c;
            }
        };
        this.table.setAutoCreateRowSorter(false);
        this.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        this.table.setFillsViewportHeight(true);
        this.table.setRowHeight(table.getRowHeight() + 2);

        this.sorter = new TableRowSorter<>(model);
        Comparator<Integer> intCmp = (a, b) -> {
            int ai = a == null ? Integer.MIN_VALUE : a.intValue();
            int bi = b == null ? Integer.MIN_VALUE : b.intValue();
            return Integer.compare(ai, bi);
        };
        sorter.setComparator(COL_NO, intCmp);
        sorter.setComparator(COL_STATUS, intCmp);
        sorter.setComparator(COL_LENGTH, intCmp);
        sorter.toggleSortOrder(COL_NO); // ASC
        sorter.toggleSortOrder(COL_NO); // DESC — newest first
        this.table.setRowSorter(sorter);
        applyVisibilityFilter();

        configureColumnWidths();

        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setMinimumSize(new Dimension(200, 100));

        // ---- Detail pane (CardLayout) ----
        this.requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        // R8: 50/50 default split. setDividerLocation(double) is a no-op until the
        // pane has nonzero size; install a HierarchyListener to fire it once after
        // the pane is shown, then immediately unregister.
        this.leftDetailHolder = new JPanel(new BorderLayout());
        this.rightDetailHolder = new JPanel(new BorderLayout());
        leftDetailHolder.add(requestEditor.uiComponent(), BorderLayout.CENTER);
        rightDetailHolder.add(responseEditor.uiComponent(), BorderLayout.CENTER);
        this.httpSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                leftDetailHolder, rightDetailHolder);
        httpSplit.setResizeWeight(0.5);
        httpSplit.addHierarchyListener(new java.awt.event.HierarchyListener() {
            @Override
            public void hierarchyChanged(java.awt.event.HierarchyEvent e) {
                if ((e.getChangeFlags() & java.awt.event.HierarchyEvent.SHOWING_CHANGED) != 0
                        && httpSplit.isShowing() && httpSplit.getWidth() > 0) {
                    SwingUtilities.invokeLater(() -> httpSplit.setDividerLocation(0.5d));
                    httpSplit.removeHierarchyListener(this);
                }
            }
        });

        JPanel emptyDetail = new JPanel(new BorderLayout());
        JLabel emptyLabel = new JLabel("Select a row to inspect", SwingConstants.CENTER);
        emptyLabel.setEnabled(false);
        emptyDetail.add(emptyLabel, BorderLayout.CENTER);

        this.detailCardLayout = new CardLayout();
        this.detailCardPanel = new JPanel(detailCardLayout);
        detailCardPanel.add(emptyDetail, CARD_EMPTY);
        detailCardPanel.add(httpSplit, CARD_HTTP);
        detailCardLayout.show(detailCardPanel, CARD_EMPTY);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, detailCardPanel);
        mainSplit.setResizeWeight(0.45);
        mainSplit.setDividerLocation(280);
        add(mainSplit, BorderLayout.CENTER);

        this.statusLabel = new JLabel("COMINT Traffic — capturing 0 entries (cap " + ComintTrafficTableModel.CAP + ")");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6));
        add(statusLabel, BorderLayout.SOUTH);

        // ---- Wiring ----
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting()) return;
            updateDetailForSelection();
        });

        cbProtobuf.addItemListener(ev -> table.repaint());
        cbGrpcWeb.addItemListener(ev -> table.repaint());
        cbMsgPack.addItemListener(ev -> table.repaint());
        cbGraphQL.addItemListener(ev -> table.repaint());
        cbWebSocket.addItemListener(ev -> table.repaint());

        rbShowAll.addItemListener(ev -> applyVisibilityFilter());
        rbVisibleOnly.addItemListener(ev -> applyVisibilityFilter());
        rbHiddenOnly.addItemListener(ev -> applyVisibilityFilter());

        table.setComponentPopupMenu(buildContextMenu());

        model.addTableModelListener(ev -> updateStatusLabel());

        // R15: restore saved language and wire change listener.
        int savedLangIdx = loadSavedLanguageIndex();
        langCombo.setSelectedIndex(savedLangIdx);
        applyLanguage(savedLangIdx);
        langCombo.addActionListener(ae -> applyLanguage(langCombo.getSelectedIndex()));
    }

    private void configureColumnWidths() {
        // R19: URL is the only column that expands freely; everything else is constrained.
        TableColumn noCol = table.getColumnModel().getColumn(COL_NO);
        noCol.setPreferredWidth(50);
        noCol.setMaxWidth(70);
        noCol.setMinWidth(40);

        TableColumn timestampCol = table.getColumnModel().getColumn(COL_TIMESTAMP);
        timestampCol.setPreferredWidth(160);
        timestampCol.setMaxWidth(190);

        TableColumn hostCol = table.getColumnModel().getColumn(COL_HOST);
        hostCol.setPreferredWidth(120);
        hostCol.setMaxWidth(200);

        TableColumn methodCol = table.getColumnModel().getColumn(COL_METHOD);
        methodCol.setPreferredWidth(55);
        methodCol.setMaxWidth(80);

        // R25: Source column — origin tool ("Proxy"/"Repeater"/...). Tight enough to
        // avoid eating URL space; wide enough for "WebSocket" / "Extension".
        TableColumn sourceCol = table.getColumnModel().getColumn(COL_SOURCE);
        sourceCol.setPreferredWidth(75);
        sourceCol.setMaxWidth(100);

        // Bug 3 fix: "WS-Bridge" no longer fits under the previous 55/75 protocol budget;
        // bumped widths so the full string + 3-digit status codes show without ellipsis.
        TableColumn protocolCol = table.getColumnModel().getColumn(COL_PROTOCOL);
        protocolCol.setPreferredWidth(75);
        protocolCol.setMaxWidth(100);

        TableColumn codecCol = table.getColumnModel().getColumn(COL_CODEC);
        codecCol.setPreferredWidth(95);
        codecCol.setMaxWidth(130);

        TableColumn statusCol = table.getColumnModel().getColumn(COL_STATUS);
        statusCol.setPreferredWidth(55);
        statusCol.setMaxWidth(75);

        TableColumn lengthCol = table.getColumnModel().getColumn(COL_LENGTH);
        lengthCol.setPreferredWidth(60);
        lengthCol.setMaxWidth(90);

        // URL: no max constraint — takes remaining horizontal space.
        TableColumn urlCol = table.getColumnModel().getColumn(COL_URL);
        urlCol.setPreferredWidth(360);

        JTableHeader header = table.getTableHeader();
        if (header != null) header.setReorderingAllowed(true);

        // R22: ALL columns left-aligned, including numeric ones — matches Burp's
        // native HTTP history (Status / Length there are left-aligned too). The
        // colored prepareRenderer override still wraps these so highlight/selection
        // backgrounds work as before.
        javax.swing.table.DefaultTableCellRenderer leftAlign = new javax.swing.table.DefaultTableCellRenderer();
        leftAlign.setHorizontalAlignment(SwingConstants.LEFT);
        for (int col = 0; col < table.getColumnCount(); col++) {
            table.getColumnModel().getColumn(col).setCellRenderer(leftAlign);
        }
    }

    private void applyVisibilityFilter() {
        // R18: visibility radios and the search box are combined into a single
        // RowFilter via RowFilter.andFilter — both must match.
        applyFilters();
    }

    private RowFilter<ComintTrafficTableModel, Integer> buildVisibilityFilter() {
        if (rbShowAll.isSelected()) return null;
        final boolean wantHidden = rbHiddenOnly.isSelected();
        return new RowFilter<ComintTrafficTableModel, Integer>() {
            @Override
            public boolean include(Entry<? extends ComintTrafficTableModel, ? extends Integer> entry) {
                int row = entry.getIdentifier();
                ComintTrafficEntry e = model.getEntry(row);
                if (e == null) return true;
                return wantHidden == e.isHidden();
            }
        };
    }

    private RowFilter<ComintTrafficTableModel, Integer> buildSearchFilter() {
        if (searchField == null) return null;
        String text = searchField.getText();
        if (text == null || text.isEmpty()) return null;
        // ReDoS protection: cap the regex source length so a pasted pathological
        // pattern (e.g. (a+)+b across 100k chars) cannot freeze the EDT inside
        // Pattern.compile or Matcher.find on every keystroke / row.
        if (text.length() > 256) {
            // Audit fix: never split a UTF-16 surrogate pair — an unpaired high
            // surrogate makes the compiled pattern reject characters it should
            // match. Back off one char if the boundary lands on a high surrogate.
            int end = 256;
            if (Character.isHighSurrogate(text.charAt(end - 1))) end--;
            text = text.substring(0, end);
        }
        try {
            // (?i) prefix makes the regex case-insensitive across all visible columns.
            return RowFilter.regexFilter("(?i)" + text);
        } catch (java.util.regex.PatternSyntaxException ex) {
            // R18: incomplete/invalid regex during typing — drop the search filter
            // until it parses again, so the user keeps seeing all rows.
            return null;
        }
    }

    private void applyFilters() {
        if (sorter == null) return;
        RowFilter<ComintTrafficTableModel, Integer> visibilityF = buildVisibilityFilter();
        RowFilter<ComintTrafficTableModel, Integer> searchF = buildSearchFilter();
        if (visibilityF == null && searchF == null) {
            sorter.setRowFilter(null);
        } else if (visibilityF == null) {
            sorter.setRowFilter(searchF);
        } else if (searchF == null) {
            sorter.setRowFilter(visibilityF);
        } else {
            java.util.List<RowFilter<? super ComintTrafficTableModel, ? super Integer>> filters
                    = new java.util.ArrayList<>(2);
            filters.add(visibilityF);
            filters.add(searchF);
            sorter.setRowFilter(RowFilter.andFilter(filters));
        }
    }

    /**
     * R18: JTextField with paint-time placeholder (Swing has none built-in).
     * The placeholder draws in disabled-text color when the field is empty
     * and not focused, exactly mirroring the standard "Search..." pattern.
     */
    static final class PlaceholderField extends JTextField {
        private String placeholder;
        PlaceholderField(int columns) {
            super(columns);
            // Repaint on focus changes so the placeholder appears/disappears.
            addFocusListener(new java.awt.event.FocusAdapter() {
                @Override public void focusGained(java.awt.event.FocusEvent e) { repaint(); }
                @Override public void focusLost(java.awt.event.FocusEvent e) { repaint(); }
            });
        }
        void setPlaceholder(String p) { this.placeholder = p; repaint(); }
        @Override
        protected void paintComponent(java.awt.Graphics g) {
            super.paintComponent(g);
            if (placeholder == null || placeholder.isEmpty()) return;
            if (!getText().isEmpty() || isFocusOwner()) return;
            java.awt.Graphics2D g2 = (java.awt.Graphics2D) g.create();
            try {
                g2.setRenderingHint(java.awt.RenderingHints.KEY_TEXT_ANTIALIASING,
                        java.awt.RenderingHints.VALUE_TEXT_ANTIALIAS_ON);
                java.awt.Color c = getDisabledTextColor();
                if (c == null) c = java.awt.Color.GRAY;
                g2.setColor(c);
                g2.setFont(getFont());
                java.awt.Insets insets = getInsets();
                int x = insets.left + 2;
                int y = insets.top + g2.getFontMetrics().getAscent();
                g2.drawString(placeholder, x, y);
            } finally {
                g2.dispose();
            }
        }
    }

    /**
     * R20: open the modal export-options dialog. The dialog runs the actual
     * export on a SwingWorker so the UI stays responsive.
     */
    private void openExportDialog() {
        try {
            new com.comint.ui.ComintExportDialog(api, this, model, codecRegistry,
                    LABELS[currentLangIdx], PERSISTENCE_EXPORT_DIR_KEY).setVisible(true);
        } catch (Throwable t) {
            logErr("openExportDialog: " + safeMsg(t));
        }
    }

    private JPopupMenu buildContextMenu() {
        JPopupMenu popup = new JPopupMenu();

        JMenuItem repeaterItem = new JMenuItem("Send to Repeater");
        repeaterItem.addActionListener(ae -> sendToRepeater());
        JMenuItem intruderItem = new JMenuItem("Send to Intruder");
        intruderItem.addActionListener(ae -> sendToIntruder());
        JMenuItem organizerItem = new JMenuItem("Send to Organizer");
        organizerItem.addActionListener(ae -> sendToOrganizer());
        JMenuItem comparerReqItem = new JMenuItem("Send to Comparer (Request)");
        comparerReqItem.addActionListener(ae -> sendToComparer(true));
        JMenuItem comparerRespItem = new JMenuItem("Send to Comparer (Response)");
        comparerRespItem.addActionListener(ae -> sendToComparer(false));
        JMenuItem activeScanItem = new JMenuItem("Do active scan");
        activeScanItem.addActionListener(ae -> doActiveScan());
        JMenuItem hideItem = new JMenuItem("Hide selected");
        hideItem.addActionListener(ae -> setHiddenForSelection(true));
        JMenuItem unhideItem = new JMenuItem("Unhide selected");
        unhideItem.addActionListener(ae -> setHiddenForSelection(false));
        this.hideMenuItem = hideItem;
        this.unhideMenuItem = unhideItem;

        popup.add(repeaterItem);
        popup.add(intruderItem);
        popup.add(organizerItem);
        popup.add(comparerReqItem);
        popup.add(comparerRespItem);
        popup.add(activeScanItem);
        popup.addSeparator();
        popup.add(hideItem);
        popup.add(unhideItem);

        popup.addPopupMenuListener(new javax.swing.event.PopupMenuListener() {
            @Override public void popupMenuWillBecomeVisible(javax.swing.event.PopupMenuEvent e) {
                ComintTrafficEntry entry = selectedEntry();
                // FIX 3: WS frame entries get a synthesized bridge request via
                // effectiveRequestForTool — enable send-to-tool items for them too.
                boolean isHttp = entry != null && entry.kind == ComintTrafficEntry.Kind.HTTP;
                boolean isWs = isWsMessageEntry(entry);
                boolean hasReq = (isHttp && entry.httpRequest != null) || isWs;
                boolean hasResp = (isHttp && entry.httpResponse != null) || isWs;
                // Audit fix: send-to-tool actions operate on a single entry — disable
                // them under multi-select so the user doesn't silently send only the
                // lowest-indexed row when they expected all five.
                int selCount = table.getSelectedRowCount();
                boolean singleRow = selCount == 1;
                repeaterItem.setEnabled(hasReq && singleRow);
                intruderItem.setEnabled(hasReq && singleRow);
                organizerItem.setEnabled(hasReq && singleRow);
                comparerReqItem.setEnabled(hasReq && singleRow);
                comparerRespItem.setEnabled(hasResp && singleRow);
                activeScanItem.setEnabled(hasReq && singleRow);
                boolean anySelected = selCount > 0;
                hideItem.setEnabled(anySelected);
                unhideItem.setEnabled(anySelected);
            }
            @Override public void popupMenuWillBecomeInvisible(javax.swing.event.PopupMenuEvent e) {}
            @Override public void popupMenuCanceled(javax.swing.event.PopupMenuEvent e) {}
        });

        return popup;
    }

    @Override
    public void onEntry(ComintTrafficEntry entry) {
        if (entry == null) return;
        SwingUtilities.invokeLater(() -> {
            try {
                model.addEntry(entry);
            } catch (Throwable t) {
                logErr("addEntry: " + safeMsg(t));
            }
        });
    }

    private ComintTrafficEntry selectedEntry() {
        int viewRow = table.getSelectedRow();
        if (viewRow < 0) return null;
        try {
            int modelRow = table.convertRowIndexToModel(viewRow);
            return model.getEntry(modelRow);
        } catch (Throwable t) {
            return null;
        }
    }

    private void setHiddenForSelection(boolean hidden) {
        int[] viewRows = table.getSelectedRows();
        if (viewRows == null || viewRows.length == 0) return;
        for (int viewRow : viewRows) {
            try {
                int modelRow = table.convertRowIndexToModel(viewRow);
                model.setHidden(modelRow, hidden);
            } catch (Throwable ignored) {}
        }
        // Re-apply filter so the hide/unhide change immediately re-shows or hides rows.
        applyVisibilityFilter();
    }

    private void updateDetailForSelection() {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) {
            detailCardLayout.show(detailCardPanel, CARD_EMPTY);
            return;
        }
        try {
            switch (e.kind) {
                case HTTP -> {
                    // The detail pane shows the ORIGINAL wire-format request and response.
                    // Burp's native editor right-click menu hands the original to Repeater
                    // etc. — Repeater's COMINT extension tab decodes for editing.
                    if (e.httpRequest != null) requestEditor.setRequest(e.httpRequest);
                    else requestEditor.setRequest(HttpRequest.httpRequest());
                    if (e.httpResponse != null) responseEditor.setResponse(e.httpResponse);
                    else responseEditor.setResponse(HttpResponse.httpResponse());
                    installPlainDetailLayout();
                    detailCardLayout.show(detailCardPanel, CARD_HTTP);
                }
                case WS_TEXT -> {
                    byte[] body = e.wsTextPayload == null ? new byte[0]
                            : e.wsTextPayload.getBytes(StandardCharsets.UTF_8);
                    showWsAsHttpDetail(e, body, "application/json; charset=utf-8");
                }
                case WS_BINARY -> {
                    byte[] body = e.wsBinaryPayload == null ? new byte[0] : e.wsBinaryPayload;
                    showWsAsHttpDetail(e, body, "application/octet-stream");
                }
            }
        } catch (Throwable t) {
            logErr("updateDetailForSelection: " + safeMsg(t));
        }
    }

    /** Render a native WebSocket frame using the same Pretty/Raw split as HTTP entries.
     *  Synthesizes an HttpRequest/HttpResponse pair so the editors get valid messages. */
    private void showWsAsHttpDetail(ComintTrafficEntry e, byte[] body, String contentType) {
        boolean clientToServer = "WS →".equals(e.method);
        int bridgePort = wsBridge != null ? safeBridgePort() : 8089;
        String wsTarget = wsTargetUrlFor(e);
        try {
            HttpService svc = HttpService.httpService("127.0.0.1", bridgePort, false);
            HttpRequest synReq = synthesizeWsBridgeRequest(svc, bridgePort, wsTarget, body, contentType);
            HttpResponse synResp = synthesizeWsBridgeResponse(body, contentType, clientToServer);
            requestEditor.setRequest(synReq);
            responseEditor.setResponse(synResp);
        } catch (Throwable t) {
            logErr("showWsAsHttpDetail synthesize: " + safeMsg(t));
            try { requestEditor.setRequest(HttpRequest.httpRequest()); } catch (Throwable ignored) {}
            try { responseEditor.setResponse(HttpResponse.httpResponse()); } catch (Throwable ignored) {}
        }
        installPlainDetailLayout();
        detailCardLayout.show(detailCardPanel, CARD_HTTP);
    }

    private int safeBridgePort() {
        try { return wsBridge != null ? wsBridge.port() : 8089; }
        catch (Throwable t) { return 8089; }
    }

    /** Best-effort ws://… or wss://… URL for the X-COMINT-WS-Target header.
     *  Prefers the upgrade request's HttpService for accurate host/port/TLS,
     *  falls back to scheme-rewriting the entry's URL. */
    private static String wsTargetUrlFor(ComintTrafficEntry e) {
        if (e.wsUpgradeRequest != null) {
            try {
                HttpService svc = e.wsUpgradeRequest.httpService();
                String path = "/";
                try {
                    String p = e.wsUpgradeRequest.path();
                    if (p != null && !p.isEmpty()) path = p;
                } catch (Throwable ignored) {}
                if (svc != null && svc.host() != null) {
                    String scheme = svc.secure() ? "wss" : "ws";
                    int port = svc.port();
                    boolean defaultPort = (svc.secure() && port == 443) || (!svc.secure() && port == 80);
                    return scheme + "://" + svc.host()
                            + (defaultPort ? "" : ":" + port) + path;
                }
            } catch (Throwable ignored) {}
        }
        String url = e.url == null ? "" : e.url;
        if (url.startsWith("https://")) return "wss://" + url.substring("https://".length());
        if (url.startsWith("http://"))  return "ws://"  + url.substring("http://".length());
        if (url.startsWith("ws://") || url.startsWith("wss://")) return url;
        return url;
    }

    /** WS-9: synthesize a bridge POST so the user can right-click → Send to Repeater
     *  on a WS frame and have Repeater hit the embedded bridge (which forwards the
     *  body to the original target as a WebSocket message and returns the response). */
    private static HttpRequest synthesizeWsBridgeRequest(HttpService svc, int bridgePort,
                                                         String wsTarget, byte[] body,
                                                         String contentType) {
        StringBuilder sb = new StringBuilder(256 + body.length);
        sb.append("POST /ws HTTP/1.1\r\n");
        sb.append("Host: 127.0.0.1:").append(bridgePort).append("\r\n");
        sb.append("X-COMINT-WS-Target: ").append(wsTarget == null ? "" : wsTarget).append("\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");
        sb.append("Content-Length: ").append(body.length).append("\r\n");
        sb.append("\r\n");
        byte[] header = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = new byte[header.length + body.length];
        System.arraycopy(header, 0, full, 0, header.length);
        System.arraycopy(body, 0, full, header.length, body.length);
        return HttpRequest.httpRequest(svc, ByteArray.byteArray(full));
    }

    private static HttpResponse synthesizeWsBridgeResponse(byte[] body, String contentType,
                                                           boolean clientToServer) {
        StringBuilder sb = new StringBuilder(128 + body.length);
        sb.append("HTTP/1.1 200 OK\r\n");
        sb.append("Content-Type: ").append(contentType).append("\r\n");
        sb.append("Content-Length: ").append(body.length).append("\r\n");
        sb.append("X-COMINT-WS-Direction: ")
                .append(clientToServer ? "client-to-server" : "server-to-client")
                .append("\r\n");
        sb.append("\r\n");
        byte[] header = sb.toString().getBytes(StandardCharsets.ISO_8859_1);
        byte[] full = new byte[header.length + body.length];
        System.arraycopy(header, 0, full, 0, header.length);
        System.arraycopy(body, 0, full, header.length, body.length);
        return HttpResponse.httpResponse(ByteArray.byteArray(full));
    }

    /** Ensure the JSplitPane holders show the bare HTTP request/response editors. */
    private void installPlainDetailLayout() {
        // If the editors are currently parented into the bridge tabs, move them back.
        if (leftDetailHolder.getComponentCount() == 0
                || leftDetailHolder.getComponent(0) != requestEditor.uiComponent()) {
            leftDetailHolder.removeAll();
            leftDetailHolder.add(requestEditor.uiComponent(), BorderLayout.CENTER);
            leftDetailHolder.revalidate();
            leftDetailHolder.repaint();
        }
        if (rightDetailHolder.getComponentCount() == 0
                || rightDetailHolder.getComponent(0) != responseEditor.uiComponent()) {
            rightDetailHolder.removeAll();
            rightDetailHolder.add(responseEditor.uiComponent(), BorderLayout.CENTER);
            rightDetailHolder.revalidate();
            rightDetailHolder.repaint();
        }
    }

    private Color backgroundForRow(int viewRow) {
        try {
            int modelRow = table.convertRowIndexToModel(viewRow);
            ComintTrafficEntry e = model.getEntry(modelRow);
            if (e == null) return null;
            if (cbProtobuf.isSelected() && "Protobuf".equals(e.codec)) return colorProtobuf;
            if (cbGrpcWeb.isSelected() && "gRPC-Web".equals(e.codec)) return colorGrpcWeb;
            if (cbMsgPack.isSelected() && "MessagePack".equals(e.codec)) return colorMsgPack;
            if (cbGraphQL.isSelected() && ("GraphQL".equals(e.codec) || "GraphQL-WS".equals(e.codec))) return colorGraphQL;
            if (cbWebSocket.isSelected()
                    && (e.kind == ComintTrafficEntry.Kind.WS_TEXT
                        || e.kind == ComintTrafficEntry.Kind.WS_BINARY
                        || "WS".equals(e.protocol)
                        || "WS-Bridge".equals(e.protocol))) {
                return colorWebSocket;
            }
            return null;
        } catch (Throwable t) {
            return null;
        }
    }

    // ---- Send-to actions (R16) ----
    //
    // Every send action decodes the body via the matched codec before handing
    // off to the Burp tool, so Comparer/Repeater/Intruder/Organizer/Scanner all
    // see human-readable JSON instead of the raw wire-format binary. If no codec
    // matches (plain HTTP), the original request/response is used as-is.

    private void sendToRepeater() {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) return;
        try {
            HttpRequest req = effectiveRequestForTool(e);
            if (req == null) return;
            HttpRequest payload = isWsMessageEntry(e) ? req : decodeRequestForTool(req, true);
            api.repeater().sendToRepeater(payload);
        } catch (Throwable t) { logErr("sendToRepeater: " + safeMsg(t)); }
    }

    private void sendToIntruder() {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) return;
        try {
            HttpRequest req = effectiveRequestForTool(e);
            if (req == null) return;
            HttpRequest payload = isWsMessageEntry(e) ? req : decodeRequestForTool(req, true);
            api.intruder().sendToIntruder(payload);
        } catch (Throwable t) { logErr("sendToIntruder: " + safeMsg(t)); }
    }

    private void sendToOrganizer() {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) return;
        try {
            HttpRequest req = effectiveRequestForTool(e);
            if (req == null) return;
            HttpResponse resp = effectiveResponseForTool(e);
            HttpRequest decReq;
            HttpResponse decResp;
            if (isWsMessageEntry(e)) {
                // Synthetic bridge request/response — already JSON-shaped, no decode needed.
                decReq = req;
                decResp = resp;
            } else {
                // Organizer is documentation-only — keep original Content-Type so the
                // entry tracks as the original protocol, but show decoded bodies.
                decReq = decodeRequestForTool(req, false);
                decResp = resp != null ? decodeResponseForTool(resp, req) : null;
            }
            if (decResp != null) {
                api.organizer().sendToOrganizer(
                        HttpRequestResponse.httpRequestResponse(decReq, decResp));
            } else {
                api.organizer().sendToOrganizer(decReq);
            }
        } catch (Throwable t) { logErr("sendToOrganizer: " + safeMsg(t)); }
    }

    private void sendToComparer(boolean request) {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) return;
        try {
            HttpRequest req = effectiveRequestForTool(e);
            HttpResponse resp = effectiveResponseForTool(e);
            if (request) {
                if (req == null) return;
                if (isWsMessageEntry(e)) {
                    api.comparer().sendToComparer(req.toByteArray());
                } else {
                    api.comparer().sendToComparer(comparerBytesForRequest(req));
                }
            } else {
                if (resp == null) return;
                if (isWsMessageEntry(e)) {
                    api.comparer().sendToComparer(resp.toByteArray());
                } else {
                    api.comparer().sendToComparer(comparerBytesForResponse(resp, req));
                }
            }
        } catch (Throwable t) { logErr("sendToComparer: " + safeMsg(t)); }
    }

    private void doActiveScan() {
        ComintTrafficEntry e = selectedEntry();
        if (e == null) return;
        try {
            HttpRequest req = effectiveRequestForTool(e);
            if (req == null) return;
            // R16: Active scan gets the decoded body but keeps the original Content-Type
            // so the AuditInsertionPointProvider re-encodes back to wire bytes for each
            // payload trial. (Repeater/Intruder change CT to application/json; Scanner does not.)
            HttpRequest scanRequest = isWsMessageEntry(e) ? req : decodeRequestForTool(req, false);
            AuditConfiguration cfg = AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            Audit audit = api.scanner().startAudit(cfg);
            if (audit != null) audit.addRequest(scanRequest);
        } catch (Throwable t) { logErr("doActiveScan: " + safeMsg(t)); }
    }

    /** True when the entry is a native WebSocket message frame (WS_TEXT/WS_BINARY). */
    private static boolean isWsMessageEntry(ComintTrafficEntry e) {
        return e != null
                && (e.kind == ComintTrafficEntry.Kind.WS_TEXT
                    || e.kind == ComintTrafficEntry.Kind.WS_BINARY);
    }

    /** HTTP request to feed Send-to-tool actions. For HTTP entries this is just the
     *  stored wire-format request; for native WebSocket frames we synthesize a bridge
     *  POST so the user's right-click sends a working bridge request to Repeater/etc. */
    private HttpRequest effectiveRequestForTool(ComintTrafficEntry e) {
        if (e == null) return null;
        if (e.kind == ComintTrafficEntry.Kind.HTTP) return e.httpRequest;
        if (!isWsMessageEntry(e)) return null;
        byte[] body;
        String contentType;
        if (e.kind == ComintTrafficEntry.Kind.WS_TEXT) {
            body = e.wsTextPayload == null ? new byte[0]
                    : e.wsTextPayload.getBytes(StandardCharsets.UTF_8);
            contentType = "application/json; charset=utf-8";
        } else {
            body = e.wsBinaryPayload == null ? new byte[0] : e.wsBinaryPayload;
            contentType = "application/octet-stream";
        }
        int port = safeBridgePort();
        HttpService svc = HttpService.httpService("127.0.0.1", port, false);
        return synthesizeWsBridgeRequest(svc, port, wsTargetUrlFor(e), body, contentType);
    }

    /** Matching synthesized response for WS frame entries; null for plain HTTP entries
     *  (which use {@code e.httpResponse} via {@link #effectiveResponseForTool}). */
    private HttpResponse effectiveResponseForTool(ComintTrafficEntry e) {
        if (e == null) return null;
        if (e.kind == ComintTrafficEntry.Kind.HTTP) return e.httpResponse;
        if (!isWsMessageEntry(e)) return null;
        boolean clientToServer = "WS →".equals(e.method);
        byte[] body;
        String contentType;
        if (e.kind == ComintTrafficEntry.Kind.WS_TEXT) {
            body = e.wsTextPayload == null ? new byte[0]
                    : e.wsTextPayload.getBytes(StandardCharsets.UTF_8);
            contentType = "application/json; charset=utf-8";
        } else {
            body = e.wsBinaryPayload == null ? new byte[0] : e.wsBinaryPayload;
            contentType = "application/octet-stream";
        }
        return synthesizeWsBridgeResponse(body, contentType, clientToServer);
    }

    /**
     * Build an HttpRequest whose body is the COMINT-decoded form. When
     * {@code switchContentTypeToJson} is true (Repeater/Intruder), the
     * Content-Type is replaced with {@code application/json} for editing.
     * When false (Organizer/Scanner), the original Content-Type is preserved
     * so downstream code can still pick the right codec / re-encode on send.
     */
    private HttpRequest decodeRequestForTool(HttpRequest req, boolean switchContentTypeToJson) {
        if (req == null) return null;
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForRequest(req).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) return req;
        byte[] body = CodecUtil.safeBodyBytes(req);
        String decoded = toolFormatString(codec, body);
        // R21: when handing the request to Repeater/Intruder, scrub the body so
        // Burp's Auto§ insertion-point detection lights up reliably:
        //   - strip a leading UTF-8 BOM (﻿) — JSON parsers and Burp both choke on it
        //   - trim trailing whitespace so the body ends cleanly on the last value
        if (switchContentTypeToJson) {
            decoded = scrubJsonForAutoDetect(decoded);
        }
        byte[] decodedBytes = decoded.getBytes(StandardCharsets.UTF_8);
        try {
            if (switchContentTypeToJson) {
                // R21: rebuild from raw HTTP/1.1 bytes — confirmed against PortSwigger
                // docs + forum threads as the reliable construction for Auto§ detection.
                // Builder methods can leave duplicate Content-Length or stale
                // Transfer-Encoding state that makes Burp's body-parameter parser
                // emit zero parameters (and Auto§ falls back to a single marker on
                // the request line). Strip those framing headers, force exact
                // Content-Type, then let HttpMessageFormatter recompute Content-Length
                // and emit a clean CRLF-separated message.
                // R10 (FIX 4): record the original Content-Type so ComintHttpHandler
                // can re-encode the JSON body back to the wire format on send.
                String origCt = CodecUtil.safeContentType(req);
                HttpRequest sanitized = req
                        .withRemovedHeader("Transfer-Encoding")
                        .withRemovedHeader("Content-Encoding")
                        .withHeader("Content-Type", "application/json");
                if (origCt != null && !origCt.isEmpty()) {
                    sanitized = sanitized.withHeader("X-COMINT-Original-Content-Type", origCt);
                }
                byte[] full = HttpMessageFormatter.formatRequest(sanitized, decodedBytes);
                full = HttpMessageFormatter.reconstructWithEncodedBody(full, decodedBytes);
                burp.api.montoya.http.HttpService service = req.httpService();
                if (service != null) {
                    return HttpRequest.httpRequest(service, ByteArray.byteArray(full));
                }
                return HttpRequest.httpRequest(ByteArray.byteArray(full));
            }
            // Organizer / Scanner path (CT preserved): keep using withBody. Auto§ is
            // not involved here; Scanner's insertion-point provider drives substitution.
            return req.withBody(ByteArray.byteArray(decodedBytes));
        } catch (Throwable t) {
            logErr("decodeRequestForTool: " + safeMsg(t));
            return req;
        }
    }

    /** R21: remove a leading BOM and trailing whitespace from a JSON body. */
    private static String scrubJsonForAutoDetect(String s) {
        if (s == null || s.isEmpty()) return "";
        int start = 0;
        if (s.charAt(0) == '﻿') start = 1;
        int end = s.length();
        while (end > start) {
            char c = s.charAt(end - 1);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') end--;
            else break;
        }
        if (start == 0 && end == s.length()) return s;
        return s.substring(start, end);
    }

    /** Build an HttpResponse whose body is the COMINT-decoded form (CT preserved). */
    private HttpResponse decodeResponseForTool(HttpResponse resp, HttpRequest associatedRequest) {
        if (resp == null) return null;
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForResponse(resp, associatedRequest).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) return resp;
        byte[] body = CodecUtil.safeBodyBytes(resp);
        String decoded = toolFormatString(codec, body);
        try {
            return resp.withBody(ByteArray.byteArray(decoded.getBytes(StandardCharsets.UTF_8)));
        } catch (Throwable t) {
            logErr("decodeResponseForTool: " + safeMsg(t));
            return resp;
        }
    }

    /**
     * R16a: bodies handed to Burp tools (Repeater / Intruder / Comparer / Organizer /
     * Scanner) must be in the tool format, NOT the codec's display format. For
     * GraphQL the wire body is already the JSON envelope tools expect, so return
     * it verbatim. For every other codec the decoded JSON IS the tool format,
     * which matches our existing decode() output.
     */
    private static String toolFormatString(ProtocolCodec codec, byte[] body) {
        if (codec != null && "GraphQL".equals(codec.name())) {
            // The display form ([query]/[variables]/[operationName]) would defeat
            // Burp's Auto§ JSON-parameter detection. Send the original envelope.
            return body == null ? "" : new String(body, StandardCharsets.UTF_8);
        }
        if (codec == null) return body == null ? "" : new String(body, StandardCharsets.UTF_8);
        try {
            String decoded = codec.decode(body);
            return decoded == null ? "" : decoded;
        } catch (Throwable t) {
            return "";
        }
    }

    /** Comparer takes raw bytes — emit start-line + headers + blank + decoded body. */
    private ByteArray comparerBytesForRequest(HttpRequest req) {
        if (req == null) return ByteArray.byteArray(new byte[0]);
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForRequest(req).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) {
            // Plain HTTP — send original message bytes as-is.
            ByteArray raw = req.toByteArray();
            return raw == null ? ByteArray.byteArray(new byte[0]) : raw;
        }
        byte[] body = CodecUtil.safeBodyBytes(req);
        byte[] decodedBytes = toolFormatString(codec, body).getBytes(StandardCharsets.UTF_8);
        return ByteArray.byteArray(HttpMessageFormatter.formatRequest(req, decodedBytes));
    }

    private ByteArray comparerBytesForResponse(HttpResponse resp, HttpRequest associatedRequest) {
        if (resp == null) return ByteArray.byteArray(new byte[0]);
        ProtocolCodec codec;
        try { codec = codecRegistry.codecForResponse(resp, associatedRequest).orElse(null); }
        catch (Throwable t) { codec = null; }
        if (codec == null) {
            ByteArray raw = resp.toByteArray();
            return raw == null ? ByteArray.byteArray(new byte[0]) : raw;
        }
        byte[] body = CodecUtil.safeBodyBytes(resp);
        byte[] decodedBytes = toolFormatString(codec, body).getBytes(StandardCharsets.UTF_8);
        return ByteArray.byteArray(HttpMessageFormatter.formatResponse(resp, decodedBytes));
    }

    // ---- R15: language switching ----

    private void applyLanguage(int idx) {
        if (idx < 0 || idx >= HEADERS.length) idx = 0;
        currentLangIdx = idx;
        String[] hs = HEADERS[idx];
        for (int i = 0; i < hs.length && i < table.getColumnCount(); i++) {
            try {
                table.getColumnModel().getColumn(i).setHeaderValue(hs[i]);
            } catch (Throwable ignored) {}
        }
        try {
            JTableHeader header = table.getTableHeader();
            if (header != null) header.repaint();
        } catch (Throwable ignored) {}
        // R17: translate COMINT-original UI strings.
        try {
            String[] L = LABELS[idx];
            highlightLabel.setText(L[L_HIGHLIGHT]);
            showLabel.setText(L[L_SHOW]);
            rbShowAll.setText(L[L_SHOW_ALL]);
            rbVisibleOnly.setText(L[L_VISIBLE_ONLY]);
            rbHiddenOnly.setText(L[L_HIDDEN_ONLY]);
            if (hideMenuItem != null) hideMenuItem.setText(L[L_HIDE_SELECTED]);
            if (unhideMenuItem != null) unhideMenuItem.setText(L[L_UNHIDE_SELECTED]);
            if (exportButton != null) exportButton.setText(L[L_EXPORT_LOGS]);
            if (searchField instanceof PlaceholderField) {
                ((PlaceholderField) searchField).setPlaceholder(L[L_SEARCH]);
            }
        } catch (Throwable ignored) {}
        // R23: status pattern is part of the language-keyed translation set; refresh now.
        try { updateStatusLabel(); } catch (Throwable ignored) {}
        // Audit fix: bridgeToggleButton's text was hard-coded English at construction
        // (line ~301) — without this refresh, a user with saved language=ru/ja/etc
        // sees "Start"/"Stop" until they toggle the bridge. refreshBridgeStatus reads
        // currentLangIdx, which we just set above.
        try { refreshBridgeStatus(); } catch (Throwable ignored) {}
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext != null) ext.setString(PERSISTENCE_LANG_KEY, LANG_CODES[idx]);
        } catch (Throwable ignored) {}
    }

    private int loadSavedLanguageIndex() {
        try {
            PersistedObject ext = api.persistence().extensionData();
            if (ext == null) return 0;
            String code = ext.getString(PERSISTENCE_LANG_KEY);
            if (code != null) {
                for (int i = 0; i < LANG_CODES.length; i++) {
                    if (LANG_CODES[i].equals(code)) return i;
                }
            }
        } catch (Throwable ignored) {}
        return 0;
    }

    private void updateStatusLabel() {
        // R23: localized pattern via MessageFormat with {0}=count and {1}=cap.
        try {
            int idx = (currentLangIdx >= 0 && currentLangIdx < LABELS.length) ? currentLangIdx : 0;
            String pattern = LABELS[idx][L_STATUS_PATTERN];
            statusLabel.setText(java.text.MessageFormat.format(pattern,
                    model.getRowCount(), ComintTrafficTableModel.CAP));
        } catch (Throwable t) {
            statusLabel.setText("COMINT Traffic — capturing " + model.getRowCount()
                    + " entries (cap " + ComintTrafficTableModel.CAP + ")");
        }
    }

    public Component component() { return this; }

    // ---- WS-4 (revised) inline bridge controls ----

    private void toggleBridge() {
        if (wsBridge == null) return;
        try {
            if (wsBridge.isRunning()) {
                wsBridge.stop();
            } else {
                int port;
                try { port = Integer.parseInt(bridgePortField.getText().trim()); }
                catch (NumberFormatException nfe) { port = ComintWsBridge.DEFAULT_PORT; }
                if (port < 1 || port > 65535) port = ComintWsBridge.DEFAULT_PORT;
                wsBridge.start(port);
            }
        } catch (Throwable t) {
            logErr("toggleBridge: " + safeMsg(t));
        }
        refreshBridgeStatus();
    }

    private void refreshBridgeStatus() {
        if (wsBridge == null) return;
        try {
            boolean running = wsBridge.isRunning();
            if (bridgeToggleButton != null) {
                String[] L = LABELS[(currentLangIdx >= 0 && currentLangIdx < LABELS.length) ? currentLangIdx : 0];
                bridgeToggleButton.setText(running ? L[L_STOP] : L[L_START]);
            }
            if (bridgeStatusDot != null) {
                bridgeStatusDot.setForeground(running ? new Color(0x22C55E) : new Color(0xEF4444));
                bridgeStatusDot.setToolTipText(running
                        ? "Bridge running on 127.0.0.1:" + wsBridge.port()
                        : "Bridge stopped");
            }
            if (bridgePortField != null && !bridgePortField.isFocusOwner()) {
                String shown = bridgePortField.getText();
                String actual = Integer.toString(wsBridge.port());
                if (!actual.equals(shown)) bridgePortField.setText(actual);
            }
        } catch (Throwable ignored) {}
    }

    /** Called from {@link com.comint.ComintExtension#extensionUnloaded()}. */
    public void teardownBridgeStatusTimer() {
        try { if (bridgeStatusTimer != null) bridgeStatusTimer.stop(); } catch (Throwable ignored) {}
    }

    private void logErr(String msg) {
        try { api.logging().logToError("COMINT Traffic: " + msg); } catch (Throwable ignored) {}
    }

    private static String safeMsg(Throwable t) {
        if (t == null) return "null";
        String m = t.getMessage();
        return (m == null || m.isEmpty()) ? t.getClass().getSimpleName() : m;
    }
}
