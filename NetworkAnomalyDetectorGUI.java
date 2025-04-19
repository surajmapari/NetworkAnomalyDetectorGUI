import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.Timer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.swing.*;
import javax.swing.text.*;

public class NetworkAnomalyDetectorGUI extends JFrame {

    // Define HTML color strings MATCHING the PAINTERS used in getPainterForAnomaly
    private static final String COLOR_CRITICAL_HTML = "#FF0000";    // ANOMALY_CRITICAL_PAINTER (Red)
    private static final String COLOR_ERROR_HTML = "#FF6464";       // ANOMALY_ERROR_PAINTER (Lighter Red)
    private static final String COLOR_SECURITY_HTML = "#C896FF";    // ANOMALY_SECURITY_GENERAL_PAINTER (Purple)
    private static final String COLOR_WARNING_HTML = "#FFB432";     // ANOMALY_WARNING_PAINTER (Orange)
    // Add a default/info color if needed (e.g., for non-anomalous but listed events)
    private static final String COLOR_DEFAULT_HTML = "#000000"; // Black (or inherit)

    // --- Constants ---
    private static final int ITEMS_PER_PAGE = 100;
    private static final int MAX_EVENTS_TO_FETCH = 1000; // Limit fetch size per refresh

    // --- UI Components ---
    private JTextPane logPane;
    private JButton refreshButton, searchButton, exportButton, resetAllButton, prevPageButton, nextPageButton, infoButton; // Added infoButton, renamed clearHighlightButton
    private JProgressBar progressBar;
    private JLabel statusLabel, pageLabel;
    private JTextField searchField;
    private JCheckBox autoRefreshCheckbox;
    private JComboBox<String> intervalBox;
    // Removed Threshold Spinners
    private JComboBox<String> anomalyFilterComboBox;
    private JComboBox<String> logNameFilterComboBox;

    // --- Data & State ---
    private List<LogEntry> allLogEntries = new ArrayList<>(); // Holds all fetched logs
    private List<LogEntry> currentlyFilteredEntries = new ArrayList<>(); // Holds logs after filtering
    private Timer autoRefreshTimer;
    private int currentPage = 1;
    private int totalPages = 1;

    // --- Highlighters ---
    // Adjusted painter usage based on removed thresholds
    private static final Highlighter.HighlightPainter ANOMALY_CRITICAL_PAINTER =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 0, 0, 180)); // Bright Red
    private static final Highlighter.HighlightPainter ANOMALY_ERROR_PAINTER =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 100, 100, 150)); // Red
    private static final Highlighter.HighlightPainter ANOMALY_WARNING_PAINTER =
            new DefaultHighlighter.DefaultHighlightPainter(new Color(255, 180, 50, 150)); // Orange
     private static final Highlighter.HighlightPainter ANOMALY_SECURITY_GENERAL_PAINTER = // General Security Anomaly
             new DefaultHighlighter.DefaultHighlightPainter(new Color(200, 150, 255, 150)); // Light Purple
    private static final Highlighter.HighlightPainter SEARCH_PAINTER =
            new DefaultHighlighter.DefaultHighlightPainter(Color.YELLOW);

    // --- Configuration ---
    private final Map<String, Integer> intervalMap = Map.of(
            "30s", 30 * 1000,
            "1 min", 60 * 1000,
            "2 min", 120 * 1000,
            "5 min", 300 * 1000
    );

    // Windows Log Names to Query
    private static final List<String> TARGET_LOG_NAMES = List.of(
            "Application", "Security", "System", "Setup"
            // "ForwardedEvents" // Uncomment if you use event forwarding
    );

    // Anomaly Types Enum - Simplified Security, added more descriptions implicitly via Info button
    enum AnomalyType {
        NONE("No Anomaly"),
        // Security Specific (Simplified - triggered by specific IDs, not counts)
        FAILED_LOGIN("Sec: Failed Login"),            // Event 4625
        ACCOUNT_LOCKOUT("Sec: Account Lockout"),         // Event 4740
        AUDIT_LOG_CLEARED("Sec: Audit Log Cleared!"),    // Event 1102
        USER_ACCOUNT_CHANGE("Sec: User Account Change"),   // Events 4720, 4722, 4726
        PRIVILEGE_ASSIGNED("Sec: Special Privilege Assigned"), // Event 4673
        GROUP_MEMBERSHIP_CHANGE("Sec: Privileged Group Changed"),// Events 4732, 4756, 4728
        // System Specific
        SERVICE_CRASH("Sys: Service Unexpected Stop"), // Event 7034, 7031
        UNEXPECTED_SHUTDOWN("Sys: Unexpected Shutdown"), // Event 6008, 41
        // General Levels (Fallback)
        CRITICAL_EVENT("General: Critical Event"), // Level 1
        ERROR_EVENT("General: Error Event"),       // Level 2
        WARNING_EVENT("General: Warning Event");    // Level 3

        private final String displayName;
        AnomalyType(String displayName) { this.displayName = displayName; }
        public String getDisplayName() { return displayName; }

        public static AnomalyType fromDisplayName(String name) {
            for (AnomalyType type : values()) {
                if (type.displayName.equals(name)) return type;
            }
            return null;
        }
    }

    // Filter ComboBox Options
    private static final String FILTER_SHOW_ALL = "Show All Logs";
    private static final String FILTER_ALL_ANOMALIES = "Show All Anomalies";
    private static final String FILTER_ALL_LOG_NAMES = "All Logs";


    // Log Entry Class (No changes needed here from previous version)
    static class LogEntry {
        String originalLine;
        String timestamp;
        String logName = "Unknown";
        int eventId = -1;
        String level = "Information"; // Default level
        String message = "";
        String sourceIp = "N/A";
        String accountName = "N/A";
        AnomalyType anomalyType = AnomalyType.NONE;

        // Patterns (pre-compiled for efficiency)
        private static final Pattern TIME_PATTERN = Pattern.compile("^TimeCreated\\s*:\\s*(.*)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        private static final Pattern ID_PATTERN = Pattern.compile("^Id\\s*:\\s*(\\d+)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        private static final Pattern LEVEL_PATTERN = Pattern.compile("^LevelDisplayName\\s*:\\s*(.*)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        private static final Pattern LOGNAME_PATTERN = Pattern.compile("^LogName\\s*:\\s*(.*)", Pattern.MULTILINE | Pattern.CASE_INSENSITIVE);
        private static final Pattern MESSAGE_PATTERN = Pattern.compile("^Message\\s*:\\s*(.*)", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        // Security Specific Patterns
        private static final Pattern IP_PATTERN = Pattern.compile("(?:Source Network Address|Client Network Address):\\s*([\\d.:a-fA-F\\-]+)", Pattern.CASE_INSENSITIVE);
        private static final Pattern ACCOUNT_PATTERN = Pattern.compile("Account Name:\\s*([^\\n\\r]+)", Pattern.CASE_INSENSITIVE);
        private static final Pattern TARGET_ACCOUNT_PATTERN = Pattern.compile("(?:Account For Which Logon Failed|Target Account Name):.+Account Name:\\s*([^\\n\\r]+)", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

        LogEntry(String block) {
            this.originalLine = block; // Store the raw block
            parseLogBlock(block);
        }

        private void parseLogBlock(String block) {
             try {
                 Matcher m;

                 m = TIME_PATTERN.matcher(block);
                 if (m.find()) this.timestamp = m.group(1).trim();

                 m = ID_PATTERN.matcher(block);
                 if (m.find()) {
                     try { this.eventId = Integer.parseInt(m.group(1).trim()); }
                     catch (NumberFormatException nfe) { this.eventId = -2; } // Indicate parsing error
                 }

                 m = LEVEL_PATTERN.matcher(block);
                 if (m.find()) this.level = m.group(1).trim();

                 m = LOGNAME_PATTERN.matcher(block);
                  if (m.find()) this.logName = m.group(1).trim();

                 m = MESSAGE_PATTERN.matcher(block);
                 if (m.find()){
                     this.message = m.group(1).trim();
                 } else {
                     this.message = block; // Fallback
                 }

                 // --- Security Specific Fields (Only parse if relevant log/ID) ---
                 if ("Security".equalsIgnoreCase(logName) && (eventId == 4625 || eventId == 4740 || eventId == 4720 || eventId == 4726 || eventId == 4732 || eventId == 4756 || eventId == 4728)) { // Added relevant IDs
                     m = IP_PATTERN.matcher(block);
                     if (m.find()) {
                         this.sourceIp = m.group(1).trim();
                         if (this.sourceIp.equals("::1") || this.sourceIp.equals("127.0.0.1")) this.sourceIp = "localhost";
                         else if (this.sourceIp.equals("-") || this.sourceIp.trim().isEmpty()) this.sourceIp = "N/A";
                     }

                     m = ACCOUNT_PATTERN.matcher(block);
                     if (m.find()) {
                         this.accountName = m.group(1).trim();
                         if (this.accountName.equals("-") || this.accountName.trim().isEmpty()) this.accountName = "N/A";
                     } else {
                          m = TARGET_ACCOUNT_PATTERN.matcher(block);
                          if (m.find()) {
                              this.accountName = m.group(1).trim();
                              if (this.accountName.equals("-") || this.accountName.trim().isEmpty()) this.accountName = "N/A";
                          }
                     }
                 }

            } catch (Exception e) {
                System.err.println("Parsing error for block: " + block.substring(0, Math.min(block.length(), 50)) + "... - " + e.getMessage());
                if (this.message.isEmpty()) this.message = block; // Ensure message has fallback
            }
        }


        @Override
        public String toString() {
            // Simple representation for the text pane
             return String.format("[%s] %s ID:%-5d Lvl:%-10s | %s",
                     timestamp != null ? timestamp : "??",
                     logName,
                     eventId,
                     level,
                     message.split("\n")[0] // Show first line of message
             );
        }
    }


    public NetworkAnomalyDetectorGUI() {
        setTitle("Network Anomaly Detector - Multi-Log");
        setSize(1250, 780); // Adjusted height slightly
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);
        setLayout(new BorderLayout(5, 5));

        try {
            UIManager.setLookAndFeel("javax.swing.plaf.nimbus.NimbusLookAndFeel");
        } catch (Exception e) { System.err.println("Nimbus L&F not found, using default."); }

        // --- Top Panel (Status & Progress) ---
        JPanel topPanel = new JPanel(new BorderLayout());
        progressBar = new JProgressBar();
        progressBar.setIndeterminate(false);
        progressBar.setVisible(false);
        progressBar.setStringPainted(true);
        progressBar.setPreferredSize(new Dimension(250, 20));
        topPanel.add(progressBar, BorderLayout.EAST);

        statusLabel = new JLabel("Status: Ready. Please Refresh.");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        topPanel.add(statusLabel, BorderLayout.CENTER);
        add(topPanel, BorderLayout.NORTH);

        // --- Center Panel (Log Display) ---
        logPane = new JTextPane();
        logPane.setEditable(false);
        logPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(logPane);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getHorizontalScrollBar().setUnitIncrement(16);
        add(scrollPane, BorderLayout.CENTER);

        // --- Bottom Control Panel (GridBagLayout) ---
        JPanel controlPanel = new JPanel(new GridBagLayout());
        controlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(3, 5, 3, 5);
        gbc.anchor = GridBagConstraints.WEST;

        // --- Row 0: Filters (Log Name, Anomaly Type, Text) ---
        gbc.gridy = 0;

        gbc.gridx = 0;
        controlPanel.add(new JLabel("Log Name:"), gbc);

        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx=0.2;
        logNameFilterComboBox = new JComboBox<>();
        logNameFilterComboBox.addItem(FILTER_ALL_LOG_NAMES);
        TARGET_LOG_NAMES.forEach(logNameFilterComboBox::addItem);
        logNameFilterComboBox.setToolTipText("Filter logs by the source Windows Event Log");
        controlPanel.add(logNameFilterComboBox, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx=0;

        gbc.gridx = 2;
        controlPanel.add(new JLabel("Anomaly Type:"), gbc);

        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx=0.3;
        anomalyFilterComboBox = new JComboBox<>();
        populateAnomalyFilterComboBox();
        anomalyFilterComboBox.setToolTipText("Filter logs by detected anomaly type");
        controlPanel.add(anomalyFilterComboBox, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx=0;

        gbc.gridx = 4;
        controlPanel.add(new JLabel("Filter Text:"), gbc);

        gbc.gridx = 5; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx=0.5;
        searchField = new JTextField();
        searchField.setToolTipText("Enter text to filter logs (case-insensitive)");
        controlPanel.add(searchField, gbc);
        gbc.fill = GridBagConstraints.NONE; gbc.weightx=0;

        gbc.gridx = 6;
        searchButton = new JButton("Apply Filters");
        searchButton.setToolTipText("Apply all selected filters (Log Name, Anomaly, Text)");
        controlPanel.add(searchButton, gbc);

        // --- Row 1: Actions & Auto Refresh ---
        gbc.gridy = 1; gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridx = 0; gbc.gridwidth = 1;
        refreshButton = new JButton("Refresh"); // Simplified text
        refreshButton.setToolTipText("Fetch latest logs ("+MAX_EVENTS_TO_FETCH+" max) and perform anomaly detection");
        controlPanel.add(refreshButton, gbc);

        gbc.gridx = 1;
        exportButton = new JButton("Export Visible");
        exportButton.setToolTipText("Export the currently displayed logs (on this page) to a text file");
        controlPanel.add(exportButton, gbc);

        // Info Button added here
        gbc.gridx = 2;
        infoButton = new JButton("Event Info");
        infoButton.setToolTipText("Show descriptions for common Event IDs flagged as anomalies");
        controlPanel.add(infoButton, gbc);

        gbc.gridx = 3; gbc.gridwidth=1; // Changed gridwidth
        JPanel autoRefreshPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        autoRefreshCheckbox = new JCheckBox("Auto Refresh");
        autoRefreshCheckbox.setToolTipText("Automatically refresh and analyze logs at the selected interval");
        autoRefreshPanel.add(autoRefreshCheckbox);
        // Removed Interval label, assumed obvious next to box
        controlPanel.add(autoRefreshPanel, gbc);

        gbc.gridx = 4; gbc.gridwidth=1; // Changed gridx & gridwidth
        intervalBox = new JComboBox<>(intervalMap.keySet().toArray(new String[0]));
        intervalBox.setSelectedItem("1 min");
        intervalBox.setToolTipText("Set the auto-refresh interval");
        controlPanel.add(intervalBox, gbc);

        // Reset All Button
        gbc.gridx = 5; gbc.gridwidth=2; // Span remaining columns
        gbc.anchor = GridBagConstraints.EAST; // Align Reset button to the right
        resetAllButton = new JButton("Reset All & Refresh");
        resetAllButton.setToolTipText("Reset all filters to default and fetch fresh logs");
        controlPanel.add(resetAllButton, gbc);
        gbc.anchor = GridBagConstraints.WEST; // Reset anchor
        gbc.fill = GridBagConstraints.NONE;

        // --- Row 2: Pagination Controls ---
         gbc.gridy = 2; gbc.gridx = 0; gbc.gridwidth = 7;
         gbc.anchor = GridBagConstraints.CENTER;
         JPanel paginationPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 0));
         prevPageButton = new JButton("<< Previous");
         pageLabel = new JLabel("Page 1 of 1");
         nextPageButton = new JButton("Next >>");
         paginationPanel.add(prevPageButton);
         paginationPanel.add(pageLabel);
         paginationPanel.add(nextPageButton);
         controlPanel.add(paginationPanel, gbc);
         gbc.anchor = GridBagConstraints.WEST;

        // --- Row 3: Removed Threshold Configuration ---
        // The layout automatically adjusts

        add(controlPanel, BorderLayout.SOUTH);


        // --- Bindings ---
        refreshButton.addActionListener(e -> loadAndAnalyzeLogs());
        searchButton.addActionListener(e -> applyFiltersAndDisplay());
        searchField.addActionListener(e -> applyFiltersAndDisplay());
        logNameFilterComboBox.addActionListener(e -> applyFiltersAndDisplay());
        anomalyFilterComboBox.addActionListener(e -> applyFiltersAndDisplay());
        exportButton.addActionListener(e -> exportLogs());
        autoRefreshCheckbox.addActionListener(e -> toggleAutoRefresh(autoRefreshCheckbox.isSelected()));
        infoButton.addActionListener(e -> showEventIdInfo()); // Bind Info Button
        resetAllButton.addActionListener(e -> resetAllFiltersAndRefresh()); // Bind Reset Button
        prevPageButton.addActionListener(e -> changePage(-1));
        nextPageButton.addActionListener(e -> changePage(1));

        updatePaginationControls();
    }

    // Helper to populate anomaly filter dropdown
    private void populateAnomalyFilterComboBox() {
        anomalyFilterComboBox.removeAllItems();
        anomalyFilterComboBox.addItem(FILTER_SHOW_ALL);
        anomalyFilterComboBox.addItem(FILTER_ALL_ANOMALIES);
        Arrays.stream(AnomalyType.values())
              .filter(type -> type != AnomalyType.NONE)
              .sorted(Comparator.comparing(AnomalyType::getDisplayName))
              .forEach(type -> anomalyFilterComboBox.addItem(type.getDisplayName()));
    }

            // --- Event ID Information Method (Expanded & Colorized - DIRECT HTML) ---
    private void showEventIdInfo() {

        // *** No separate helper function needed for this method ***

        // Use String.formatted() to insert the HTML color spans directly
        String infoText = """
                <html><body>
                <h2>Common Windows Event IDs for Anomaly Detection</h2>
                <i>(Colors indicate typical severity/type:
                %s, %s, %s, %s. Context is key!)</i><br><br>

                <b><u>Security Log: Logon/Logoff & Account Activity</u></b><br>
                 * <b>4624:</b> Successful Logon (Note type: 2=Interactive, 3=Network, 10=RemoteInteractive)<br>
                 %s<br>
                 * <b>4634:</b> Successful Logoff<br>
                 * <b>4647:</b> User Initiated Logoff<br>
                 * <b>4648:</b> Logon attempt using explicit credentials (RunAs)<br>
                 %s<br>
                 * <b>4768:</b> Kerberos Authentication Ticket (TGT) Requested (Success)<br>
                 * <b>4769:</b> Kerberos Service Ticket Requested (Success)<br>
                 %s<br>
                 %s<br>

                <b><u>Security Log: Account Management</u></b><br>
                 %s<br>
                 %s<br>
                 * <b>4723:</b> Attempt to change account password<br>
                 * <b>4724:</b> Attempt to reset account password<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>

                <b><u>Security Log: Group Management</u></b><br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>

                <b><u>Security Log: Policy Change & System Events</u></b><br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 %s<br>
                 * <b>5156:</b> Firewall permitted network connection<br>
                 %s<br>

                <b><u>System Log: Service & System Stability</u></b><br>
                 %s<br>
                 %s<br>
                 * <b>7036:</b> Service entered running/stopped state (Track service availability)<br>
                 %s<br>
                 %s<br>
                 * <b>6005:</b> Event Log Service Started<br>
                 * <b>6006:</b> Event Log Service Stopped (Clean shutdown)<br>
                 %s<br>
                 %s<br>
                 * <b>1074:</b> User initiated restart/shutdown (Includes reason if provided)<br>

                <b><u>Application Log: Common Issues</u></b><br>
                 * Event IDs vary greatly by application (MSSQL, Exchange, etc.).<br>
                 %s<br>

                <b><u>Other Potential Logs (If Enabled):</u></b><br>
                 %s<br>
                 * <b>Task Scheduler:</b> Task registration (106), completion (102), failure (101, 103)<br>
                 %s<br>
                 %s<br><br>

                <b><u>General Levels:</u></b><br>
                 %s<br>
                 %s<br>
                 %s<br>
                 * <b>Information (4):</b> Normal operational messages.<br>
                 * <b>Verbose (5):</b> Detailed tracing information.<br>
                </body></html>
                """.formatted(
                // Legend Items - Use direct HTML concatenation/formatting
                "<span style='color: " + COLOR_CRITICAL_HTML + ";'>Critical</span>",
                "<span style='color: " + COLOR_ERROR_HTML + ";'>Error</span>",
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>Security Change/Issue</span>",
                "<span style='color: " + COLOR_WARNING_HTML + ";'>Warning</span>",

                // Event Descriptions - Use direct HTML concatenation/formatting for color spans
                // Match color to the painter used in getPainterForAnomaly for the corresponding AnomalyType
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4625:</b> Failed Logon (Check reason/sub-status code in message)</span>", // FAILED_LOGIN -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4740:</b> Account Lockout (Often follows multiple 4625 events)</span>", // ACCOUNT_LOCKOUT -> SECURITY
                "<span style='color: " + COLOR_WARNING_HTML + ";'>* <b>4771:</b> Kerberos Pre-Authentication Failed (Often bad password before 4625)</span>", // WARNING (Not specific AnomalyType)
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>4776:</b> Domain Controller failed NTLM authentication (Check source workstation)</span>", // ERROR (Not specific AnomalyType)

                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4720:</b> User Account Created</span>",          // USER_ACCOUNT_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4722:</b> User Account Enabled</span>",           // USER_ACCOUNT_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4725:</b> User Account Disabled</span>",          // USER_ACCOUNT_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4726:</b> User Account Deleted</span>",           // USER_ACCOUNT_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4738:</b> User Account Changed (Check properties modified)</span>", // USER_ACCOUNT_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4781:</b> Name of an account changed</span>",     // USER_ACCOUNT_CHANGE -> SECURITY (Implicitly)
                "<span style='color: " + COLOR_WARNING_HTML + ";'>* <b>4798:</b> User's local group membership enumerated</span>", // WARNING (Reconnaissance)

                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4728:</b> Member Added to Security-Enabled Global Group</span>",    // GROUP_MEMBERSHIP_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4729:</b> Member Removed from Security-Enabled Global Group</span>", // GROUP_MEMBERSHIP_CHANGE -> SECURITY (Implicitly)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4732:</b> Member Added to Security-Enabled Local Group (e.g., Administrators)</span>", // GROUP_MEMBERSHIP_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4733:</b> Member Removed from Security-Enabled Local Group</span>", // GROUP_MEMBERSHIP_CHANGE -> SECURITY (Implicitly)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4756:</b> Member Added to Security-Enabled Universal Group (e.g., Domain Admins)</span>", // GROUP_MEMBERSHIP_CHANGE -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4757:</b> Member Removed from Security-Enabled Universal Group</span>",// GROUP_MEMBERSHIP_CHANGE -> SECURITY (Implicitly)

                "<span style='color: " + COLOR_CRITICAL_HTML + ";'>* <b>1102:</b> Audit Log Cleared (<b>Highly Suspicious!</b>)</span>", // AUDIT_LOG_CLEARED -> CRITICAL
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4672:</b> Special Privileges Assigned to New Logon (Admin equivalent rights)</span>", // PRIVILEGE_ASSIGNED -> SECURITY (Implicitly)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4673:</b> Privileged Service Called (Sensitive operations)</span>", // PRIVILEGE_ASSIGNED -> SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4704:</b> User Right Assigned (e.g., SeDebugPrivilege)</span>", // PRIVILEGE_ASSIGNED -> SECURITY (Implicitly)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4719:</b> System Audit Policy Changed</span>",      // SECURITY (General Change)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4946:</b> Firewall Rule Added exception list</span>", // SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4947:</b> Firewall Rule Modified in exception list</span>",// SECURITY
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>4950:</b> Firewall Setting Changed</span>",          // SECURITY
                "<span style='color: " + COLOR_WARNING_HTML + ";'>* <b>5157:</b> Firewall blocked network connection (Potential scans/attacks)</span>", // WARNING

                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>7031:</b> Service Terminated Unexpectedly</span>", // SERVICE_CRASH -> ERROR
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>7034:</b> Service Terminated Unexpectedly (Another common ID)</span>",// SERVICE_CRASH -> ERROR
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>7040:</b> Service start type changed (Auto -> Disabled etc.)</span>", // SECURITY (Potential config change)
                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>7045:</b> Service Installed (Check legitimacy)</span>", // SECURITY (Needs verification)
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>6008:</b> Unexpected Shutdown (System didn't shut down cleanly)</span>", // UNEXPECTED_SHUTDOWN -> ERROR
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>  41:</b> Kernel-Power (System rebooted without cleanly shutting down - often after 6008/BSOD)</span>", // UNEXPECTED_SHUTDOWN -> ERROR

                "<span style='color: " + COLOR_WARNING_HTML + ";'>* Look for high volumes of errors/warnings from specific sources.</span>", // WARNING

                "<span style='color: " + COLOR_SECURITY_HTML + ";'>* <b>PowerShell Operational:</b> Script Block Logging (4104 - reveals script content), Module Logging (4103)</span>", // SECURITY
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>Windows Defender:</b> Malware detection events (e.g., 1006, 1116, 1117)</span>", // ERROR (Detection is an error state)
                "<span style='color: " + COLOR_WARNING_HTML + ";'>* <b>DNS Client Events:</b> Errors resolving names.</span>", // WARNING

                "<span style='color: " + COLOR_CRITICAL_HTML + ";'>* <b>Critical (1):</b> Severe system-wide issues.</span>", // CRITICAL_EVENT -> CRITICAL
                "<span style='color: " + COLOR_ERROR_HTML + ";'>* <b>Error (2):</b> Significant problems, loss of functionality likely.</span>", // ERROR_EVENT -> ERROR
                "<span style='color: " + COLOR_WARNING_HTML + ";'>* <b>Warning (3):</b> Potential issues, may lead to errors.</span>" // WARNING_EVENT -> WARNING
            );

        // Use JEditorPane for basic HTML rendering
        JEditorPane editorPane = new JEditorPane("text/html", infoText);
        editorPane.setEditable(false);
        editorPane.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editorPane.setFont(this.getFont()); // Use the default frame font

        // Ensure JEditorPane background matches JOptionPane background
        UIDefaults defaults = UIManager.getLookAndFeelDefaults();
        editorPane.setBackground(defaults.getColor("OptionPane.background"));


        JScrollPane scrollPane = new JScrollPane(editorPane);
        scrollPane.setPreferredSize(new Dimension(650, 500)); // Adjusted size

        JOptionPane.showMessageDialog(this, scrollPane, "Common Anomaly Event IDs (with Severity Colors)", JOptionPane.INFORMATION_MESSAGE);
    }


    private void setStatus(String message, boolean busy) {
        SwingUtilities.invokeLater(() -> {
            statusLabel.setText("Status: " + message);
            progressBar.setIndeterminate(busy);
            progressBar.setVisible(busy);
            refreshButton.setEnabled(!busy);
            searchButton.setEnabled(!busy);
            logNameFilterComboBox.setEnabled(!busy);
            anomalyFilterComboBox.setEnabled(!busy);
            searchField.setEnabled(!busy);
            infoButton.setEnabled(!busy);
            resetAllButton.setEnabled(!busy);
            prevPageButton.setEnabled(!busy && currentPage > 1);
            nextPageButton.setEnabled(!busy && currentPage < totalPages);
        });
    }


    private void loadAndAnalyzeLogs() {
        setStatus("Fetching & analyzing logs...", true);
        logPane.setText("");
        allLogEntries.clear();
        currentlyFilteredEntries.clear();
        currentPage = 1;
        totalPages = 1;
        clearHighlights(); // Clear painters on the pane

        SwingWorker<List<LogEntry>, String> worker = new SwingWorker<>() {
            private List<LogEntry> fetchedEntries = new ArrayList<>();
            private String errorMessage = null;
            private long currentAnomalyCount = 0;

            @Override
            protected List<LogEntry> doInBackground() throws Exception {
                publish("Fetching logs from " + String.join(", ", TARGET_LOG_NAMES) + "...");
                progressBar.setString("Fetching...");

                // Adjusted PowerShell Command - Simpler, gets all levels + specific Security IDs
                // Rely on Get-WinEvent's default newest-first ordering
                String logNameFilter = "(@('" + String.join("','", TARGET_LOG_NAMES) + "'))";
                String securityIds = "@(4625, 4740, 1102, 4720, 4722, 4726, 4673, 4732, 4756, 4728)"; // IDs to fetch specifically
                String commandFilter = String.format(
                    "Get-WinEvent -FilterHashtable @{LogName=%s} -MaxEvents %d | Select-Object TimeCreated, LogName, Id, LevelDisplayName, Message | Format-List ; " +
                    "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=%s} -MaxEvents %d | Select-Object TimeCreated, LogName, Id, LevelDisplayName, Message | Format-List",
                    logNameFilter, MAX_EVENTS_TO_FETCH, securityIds, MAX_EVENTS_TO_FETCH
                );

                String[] command = {"powershell.exe", "-NoProfile", "-Command", commandFilter };

                try {
                    ProcessBuilder pb = new ProcessBuilder(command);
                    pb.redirectErrorStream(true);
                    Process process = pb.start();

                    Map<String, LogEntry> uniqueEntries = new LinkedHashMap<>();

                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                        String line;
                        StringBuilder currentEntryText = new StringBuilder();
                        while ((line = reader.readLine()) != null) {
                            if (line.trim().isEmpty() && currentEntryText.length() > 0) {
                                if (currentEntryText.toString().matches("(?s)^TimeCreated\\s*:.*")) {
                                    String block = currentEntryText.toString().trim();
                                    LogEntry entry = new LogEntry(block);
                                    String key = entry.timestamp + "|" + entry.eventId + "|" + entry.logName + "|" + entry.message.hashCode(); // Improved key for deduplication
                                    uniqueEntries.putIfAbsent(key, entry);
                                }
                                currentEntryText.setLength(0);
                            } else if (!line.trim().isEmpty()) {
                                if (line.matches("^TimeCreated\\s*:.*") && currentEntryText.length() > 0) {
                                    String block = currentEntryText.toString().trim();
                                     LogEntry entry = new LogEntry(block);
                                     String key = entry.timestamp + "|" + entry.eventId + "|" + entry.logName + "|" + entry.message.hashCode();
                                     uniqueEntries.putIfAbsent(key, entry);
                                    currentEntryText.setLength(0);
                                }
                                currentEntryText.append(line).append("\n");
                            }
                        }
                         if (currentEntryText.length() > 0 && currentEntryText.toString().matches("(?s)^TimeCreated\\s*:.*")) {
                              String block = currentEntryText.toString().trim();
                              LogEntry entry = new LogEntry(block);
                              String key = entry.timestamp + "|" + entry.eventId + "|" + entry.logName + "|" + entry.message.hashCode();
                              uniqueEntries.putIfAbsent(key, entry);
                         }
                    } // end reader try

                    fetchedEntries.addAll(uniqueEntries.values());

                    // Sort entries chronologically DESCENDING (newest first)
                    // Assuming timestamp format is reasonably sortable as string (like ISO 8601 or consistent system format)
                    fetchedEntries.sort(Comparator.comparing((LogEntry e) -> e.timestamp,
                                                             Comparator.nullsLast(Comparator.reverseOrder())));


                    int exitCode = process.waitFor();
                    if (exitCode != 0) {
                        System.err.println("Warning: PowerShell process exited with code " + exitCode);
                        if (fetchedEntries.isEmpty()) {
                             errorMessage = "❌ PowerShell Error (Code " + exitCode + "). Run as Admin? Check command.";
                             fetchedEntries.add(new LogEntry(errorMessage));
                        }
                    }

                } catch (IOException | InterruptedException ex) {
                    errorMessage = "❌ Error running PowerShell: " + ex.getMessage();
                    System.err.println(errorMessage); ex.printStackTrace();
                    fetchedEntries.add(new LogEntry(errorMessage));
                }

                if (fetchedEntries.isEmpty() && errorMessage == null) {
                    errorMessage = "⚠️ No relevant events found in the specified logs.";
                    fetchedEntries.add(new LogEntry(errorMessage));
                }

                // --- Anomaly Analysis (Simpler: Based on ID/Level only) ---
                publish("Analyzing " + fetchedEntries.size() + " unique events...");
                progressBar.setString("Analyzing...");

                 for (LogEntry entry : fetchedEntries) { // Iterate directly over the final sorted list
                      entry.anomalyType = AnomalyType.NONE; // Reset

                      // Assign anomaly based on Log Name, Event ID, or Level
                      if ("Security".equalsIgnoreCase(entry.logName)) {
                           switch (entry.eventId) {
                               case 4625: entry.anomalyType = AnomalyType.FAILED_LOGIN; break;
                               case 4740: entry.anomalyType = AnomalyType.ACCOUNT_LOCKOUT; break;
                               case 1102: entry.anomalyType = AnomalyType.AUDIT_LOG_CLEARED; break;
                               case 4720: case 4722: case 4726: entry.anomalyType = AnomalyType.USER_ACCOUNT_CHANGE; break;
                               case 4673: entry.anomalyType = AnomalyType.PRIVILEGE_ASSIGNED; break;
                               case 4732: case 4756: case 4728: entry.anomalyType = AnomalyType.GROUP_MEMBERSHIP_CHANGE; break;
                           }
                      } else if ("System".equalsIgnoreCase(entry.logName)) {
                           switch (entry.eventId) {
                               case 7034: case 7031: entry.anomalyType = AnomalyType.SERVICE_CRASH; break;
                               case 6008: case 41: entry.anomalyType = AnomalyType.UNEXPECTED_SHUTDOWN; break;
                           }
                      }

                      // General Level-Based Anomaly (if not already flagged by specific ID)
                      if (entry.anomalyType == AnomalyType.NONE) {
                            if ("Critical".equalsIgnoreCase(entry.level)) entry.anomalyType = AnomalyType.CRITICAL_EVENT;
                            else if ("Error".equalsIgnoreCase(entry.level)) entry.anomalyType = AnomalyType.ERROR_EVENT;
                            else if ("Warning".equalsIgnoreCase(entry.level)) entry.anomalyType = AnomalyType.WARNING_EVENT;
                      }
                 } // End analysis loop

                // Count total anomalies
                currentAnomalyCount = fetchedEntries.stream().filter(e -> e.anomalyType != AnomalyType.NONE).count();

                return fetchedEntries; // Return the final, sorted list
            }

            @Override
            protected void process(List<String> chunks) {
                for (String status : chunks) { setStatus(status, true); }
            }

            @Override
            protected void done() {
                try {
                    allLogEntries = get(); // Get the final sorted list
                    applyFiltersAndDisplay(); // Apply current filters (usually defaults after reset) and show first page

                    String finalStatus;
                     if (errorMessage != null && allLogEntries.stream().allMatch(e -> e.eventId <= 0)) {
                        finalStatus = errorMessage;
                    } else if (errorMessage != null) {
                         finalStatus = String.format("⚠️ Fetched %d events (potential errors). Detected %d anomalies.",
                                                    allLogEntries.size(), currentAnomalyCount);
                    } else {
                        finalStatus = String.format("Fetched %d events. Detected %d anomalies.",
                                                    allLogEntries.size(), currentAnomalyCount);
                    }
                    setStatus(finalStatus, false);
                    progressBar.setString("Done");

                } catch (Exception e) {
                     setStatus("❌ Error processing results: " + e.getMessage(), false);
                     logPane.setText("Error displaying results:\n" + e.getMessage());
                    e.printStackTrace();
                }
            }
        };
        worker.execute();
    }

    // Central method to apply all filters and update display
    private void applyFiltersAndDisplay() {
        filterLogEntries();
        currentPage = 1;
        displayCurrentPage();
    }

    // Applies filters based on UI selections, updates currentlyFilteredEntries
    private void filterLogEntries() {
        String selectedLogName = (String) logNameFilterComboBox.getSelectedItem();
        String selectedAnomalyFilter = (String) anomalyFilterComboBox.getSelectedItem();
        String keyword = searchField.getText().trim().toLowerCase();

        // Debugging filter application
        System.out.println("Filtering - Log: " + selectedLogName + ", Anomaly: " + selectedAnomalyFilter + ", Text: '" + keyword + "'");

        currentlyFilteredEntries = allLogEntries.stream()
                .filter(entry -> entry.eventId > 0) // Exclude pseudo error messages
                .filter(entry -> FILTER_ALL_LOG_NAMES.equals(selectedLogName) || entry.logName.equalsIgnoreCase(selectedLogName))
                .filter(entry -> {
                    // Anomaly Filter Logic
                    if (FILTER_SHOW_ALL.equals(selectedAnomalyFilter)) {
                        return true; // Show all if 'Show All Logs' is selected
                    } else if (FILTER_ALL_ANOMALIES.equals(selectedAnomalyFilter)) {
                        boolean isAnomaly = entry.anomalyType != AnomalyType.NONE;
                        // System.out.println(" Event ID " + entry.eventId + " Is Anomaly? " + isAnomaly + " (Type: " + entry.anomalyType + ")"); // Debugging line
                        return isAnomaly; // Show if 'Show All Anomalies' is selected AND it's an anomaly
                    } else {
                        // Specific Anomaly Type Filter
                        AnomalyType type = AnomalyType.fromDisplayName(selectedAnomalyFilter);
                        return type != null && entry.anomalyType == type; // Show if specific type matches
                    }
                })
                .filter(entry -> keyword.isEmpty() || entry.originalLine.toLowerCase().contains(keyword)) // Text Filter
                .collect(Collectors.toList());

        totalPages = (int) Math.ceil((double) currentlyFilteredEntries.size() / ITEMS_PER_PAGE);
        if (totalPages == 0) totalPages = 1;
        System.out.println("Filtering resulted in " + currentlyFilteredEntries.size() + " entries across " + totalPages + " pages.");
    }


    // Displays the logs corresponding to the current page from currentlyFilteredEntries
    private void displayCurrentPage() {
        logPane.setText("");
        Highlighter highlighter = logPane.getHighlighter();
        highlighter.removeAllHighlights(); // Clear previous highlights on redraw

        if (currentlyFilteredEntries.isEmpty() && !progressBar.isVisible()) {
            logPane.setText("ℹ️ No logs match the current filter criteria.");
            updatePaginationControls();
            updateStatusForFilter(0, 0);
            return;
        }

        StyledDocument doc = logPane.getStyledDocument();
        SimpleAttributeSet normalAttrs = new SimpleAttributeSet();
        StyleConstants.setFontFamily(normalAttrs, "Monospaced");
        StyleConstants.setFontSize(normalAttrs, 12);

        int startIndex = (currentPage - 1) * ITEMS_PER_PAGE;
        int endIndex = Math.min(startIndex + ITEMS_PER_PAGE, currentlyFilteredEntries.size());

        int displayedOnPage = 0;
        int anomaliesOnPage = 0;
        int currentOffset = 0;
        String keyword = searchField.getText().trim().toLowerCase();

        // Make sure startIndex is valid before proceeding
         if (startIndex < currentlyFilteredEntries.size()) {
             for (int i = startIndex; i < endIndex; i++) {
                 LogEntry entry = currentlyFilteredEntries.get(i);
                 String line = entry.toString() + "\n";

                 try {
                     int startOffset = currentOffset;
                     int endOffset = startOffset + line.length();
                     doc.insertString(startOffset, line, normalAttrs);

                     // Anomaly Highlighting
                     if (entry.anomalyType != AnomalyType.NONE) {
                         Highlighter.HighlightPainter painter = getPainterForAnomaly(entry.anomalyType); // Simpler call now
                         if (painter != null) {
                             try {
                                 highlighter.addHighlight(startOffset, endOffset - 1, painter);
                             } catch (BadLocationException ble) { /* Ignore */ }
                         }
                         anomaliesOnPage++;
                     }

                     // Search Highlighting
                     if (!keyword.isEmpty()) {
                         String displayedTextLower = line.toLowerCase();
                         int kwIdx = displayedTextLower.indexOf(keyword);
                         while (kwIdx >= 0) {
                             try {
                                 int kwStart = startOffset + kwIdx;
                                 int kwEnd = kwStart + keyword.length();
                                 highlighter.addHighlight(kwStart, kwEnd, SEARCH_PAINTER);
                                 kwIdx = displayedTextLower.indexOf(keyword, kwIdx + 1);
                             } catch (BadLocationException ble) { break; }
                         }
                     }

                     currentOffset = endOffset;
                     displayedOnPage++;

                 } catch (BadLocationException e) {
                     e.printStackTrace();
                     setStatus("Error updating display.", false);
                     return;
                 }
             }
         } else if (!allLogEntries.isEmpty() && !progressBar.isVisible()){
             logPane.setText("ℹ️ No logs found for this page with current filters.");
         }


        logPane.setCaretPosition(0);
        updatePaginationControls();
        if (!progressBar.isVisible()) {
            updateStatusForFilter(displayedOnPage, anomaliesOnPage);
        }
    }

     // Helper to get the correct painter based on anomaly type (level no longer needed here)
     private Highlighter.HighlightPainter getPainterForAnomaly(AnomalyType type) {
         switch (type) {
             // Critical/Severe first
             case AUDIT_LOG_CLEARED:
             case CRITICAL_EVENT:
                 return ANOMALY_CRITICAL_PAINTER;

             // Errors
             case SERVICE_CRASH:
             case UNEXPECTED_SHUTDOWN:
             case ERROR_EVENT:
                 return ANOMALY_ERROR_PAINTER;

             // Specific Security Events (treated distinctly)
             case FAILED_LOGIN:
             case ACCOUNT_LOCKOUT:
             case USER_ACCOUNT_CHANGE:
             case PRIVILEGE_ASSIGNED:
             case GROUP_MEMBERSHIP_CHANGE:
                 return ANOMALY_SECURITY_GENERAL_PAINTER; // Purple for these

             // Warnings
             case WARNING_EVENT:
                 return ANOMALY_WARNING_PAINTER;

             // Should not happen if logic is correct, but have a fallback
             case NONE:
             default:
                 return null; // No highlight for NONE or unknown
         }
     }


    // Updates the status bar based on filtering and pagination results
    private void updateStatusForFilter(int displayedOnPage, int anomaliesOnPage) {
        String filterDesc = "";
        String logFilter = (String) logNameFilterComboBox.getSelectedItem();
        String anomalyFilter = (String) anomalyFilterComboBox.getSelectedItem();
        String textFilter = searchField.getText().trim();

        if (!FILTER_ALL_LOG_NAMES.equals(logFilter)) filterDesc += "Log: " + logFilter;
        if (!FILTER_SHOW_ALL.equals(anomalyFilter)) {
            if (!filterDesc.isEmpty()) filterDesc += " | ";
            filterDesc += "Anomaly: " + anomalyFilter;
        }
        if (!textFilter.isEmpty()) {
            if (!filterDesc.isEmpty()) filterDesc += " | ";
            filterDesc += "Text: '" + textFilter + "'";
        }
        if (filterDesc.isEmpty()) filterDesc = "All Logs";

        setStatus(String.format("Showing %d logs (%d anomalies) on page %d of %d. Total matching: %d. Filter: [%s]",
                displayedOnPage, anomaliesOnPage, currentPage, totalPages, currentlyFilteredEntries.size(), filterDesc), false);
    }

    // Updates the enabled state and text of pagination controls
    private void updatePaginationControls() {
         pageLabel.setText(String.format("Page %d of %d", currentPage, totalPages));
         prevPageButton.setEnabled(currentPage > 1 && !progressBar.isVisible());
         nextPageButton.setEnabled(currentPage < totalPages && !progressBar.isVisible());
    }

    // Handles changing the page
    private void changePage(int direction) {
        int newPage = currentPage + direction;
        if (newPage >= 1 && newPage <= totalPages) {
            currentPage = newPage;
            displayCurrentPage();
        }
    }

    // --- Reset All Method ---
    private void resetAllFiltersAndRefresh() {
        System.out.println("Resetting filters and refreshing...");
        // Reset filter components to default
        logNameFilterComboBox.setSelectedItem(FILTER_ALL_LOG_NAMES);
        anomalyFilterComboBox.setSelectedItem(FILTER_SHOW_ALL);
        searchField.setText("");

        // Stop auto-refresh if it's running
        if (autoRefreshCheckbox.isSelected()) {
            autoRefreshCheckbox.doClick(); // This will trigger toggleAutoRefresh(false)
        }

        // Clear current display immediately (optional, looks cleaner)
        logPane.setText("");
        allLogEntries.clear();
        currentlyFilteredEntries.clear();
        currentPage = 1;
        totalPages = 1;
        updatePaginationControls();
        statusLabel.setText("Status: Resetting and fetching fresh logs...");

        // Trigger a fresh load and analysis
        loadAndAnalyzeLogs();
    }


    // Clears all highlight painters from the log pane (Used internally now)
    private void clearHighlights() {
        if (logPane != null && logPane.getHighlighter() != null) {
            logPane.getHighlighter().removeAllHighlights();
        }
    }


    private void exportLogs() {
        // Export only the logs currently visible on the page
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Visible Logs (Page " + currentPage + ")");
        String timeStamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        String filters = ((String)logNameFilterComboBox.getSelectedItem()).replace(" ", "_") + "_" +
                         ((String)anomalyFilterComboBox.getSelectedItem()).replace(" ", "_");
        fileChooser.setSelectedFile(new File("network_logs_" + filters + "_Page" + currentPage + "_" + timeStamp + ".txt"));
        int option = fileChooser.showSaveDialog(this);

        if (option == JFileChooser.APPROVE_OPTION) {
            File file = fileChooser.getSelectedFile();
            try (BufferedWriter writer = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
                 logPane.write(writer);
                 setStatus("✅ Visible logs exported to " + file.getName(), false);
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "❌ Error exporting logs: " + ex.getMessage(), "Export Error", JOptionPane.ERROR_MESSAGE);
                setStatus("Error exporting logs.", false);
            }
        }
    }

    private void toggleAutoRefresh(boolean enabled) {
        if (enabled) {
            if (autoRefreshTimer != null) autoRefreshTimer.cancel();
            int interval = intervalMap.getOrDefault(intervalBox.getSelectedItem().toString(), 60000);
            autoRefreshTimer = new Timer("LogAutoRefreshTimer", true);
            autoRefreshTimer.scheduleAtFixedRate(new TimerTask() {
                @Override
                public void run() {
                    SwingUtilities.invokeLater(() -> {
                        if (!progressBar.isVisible()) {
                            System.out.println(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - Auto-refresh triggered...");
                            loadAndAnalyzeLogs();
                        } else {
                            System.out.println(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - Skipping auto-refresh, busy.");
                        }
                    });
                }
            }, interval, interval);
            setStatus("Auto-refresh enabled (" + intervalBox.getSelectedItem() + ")", false);
            intervalBox.setEnabled(false);
            refreshButton.setEnabled(false);
        } else {
            if (autoRefreshTimer != null) {
                autoRefreshTimer.cancel();
                autoRefreshTimer = null;
                System.out.println(new SimpleDateFormat("HH:mm:ss").format(new Date()) + " - Auto-refresh stopped.");
            }
            if (!progressBar.isVisible()) setStatus("Auto-refresh stopped. Ready.", false);
            intervalBox.setEnabled(true);
            refreshButton.setEnabled(true);
        }
    }

    // --- Main Method ---
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            NetworkAnomalyDetectorGUI gui = new NetworkAnomalyDetectorGUI();
            // Check for Admin rights (basic check)
            boolean isAdmin = false;
            try { // Use a command that requires admin privileges
                 ProcessBuilder pb = new ProcessBuilder("cmd", "/c", "openfiles > nul 2>&1");
                 // Alternative: "fsutil dirty query %systemdrive% > nul 2>&1"
                 Process p = pb.start();
                 isAdmin = (p.waitFor() == 0);
             } catch (Exception io) { /* Ignore, assume not admin */ }

            if (!isAdmin) {
                 JOptionPane.showMessageDialog(gui,
                    "WARNING: Application likely lacks administrator privileges.\n" +
                    "Fetching Security logs and some System logs might fail.\n\n" +
                    "Please restart the application 'Run as administrator' for full functionality.",
                    "Permissions Warning", JOptionPane.WARNING_MESSAGE);
            }

            gui.setVisible(true);
        });
    }
}