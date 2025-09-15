"""
Main Window GUI for Advanced Security Scanner
"""

import sys
import logging
from pathlib import Path
from typing import Dict, Any, Optional

from PyQt5.QtWidgets import (
    QMainWindow, QTabWidget, QVBoxLayout, QHBoxLayout, QWidget,
    QSplitter, QTreeWidget, QTreeWidgetItem, QTextEdit, QLineEdit,
    QPushButton, QComboBox, QGroupBox, QLabel, QProgressBar,
    QTableWidget, QTableWidgetItem, QCheckBox, QSpinBox,
    QMenuBar, QStatusBar, QAction, QToolBar, QFrame,
    QScrollArea, QGridLayout, QMessageBox, QFileDialog
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSettings, QSize
)
from PyQt5.QtGui import (
    QFont, QIcon, QPixmap, QPalette, QColor, QKeySequence
)

from core.config_manager import ConfigManager
from core.logger import get_security_logger
from gui.scan_widgets import ScanConfigWidget, ResultsWidget
from gui.dashboard import DashboardWidget
from gui.target_manager import TargetManagerWidget
from gui.report_viewer import ReportViewerWidget

class SecurityScannerMainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        
        self.config_manager = config_manager
        self.security_logger = get_security_logger(__name__)
        self.logger = logging.getLogger(__name__)
        
        self.current_scans = {}  # Track running scans
        self.settings = QSettings()
        
        # Initialize UI
        self.init_ui()
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_status_bar()
        self.apply_dark_theme()
        
        # Load settings
        self.load_window_settings()
        
        self.logger.info("Main window initialized")
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Advanced Security Scanner v1.0")
        self.setMinimumSize(1200, 800)
        
        # Central widget with tab layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QVBoxLayout(central_widget)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # Create main tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabsClosable(False)
        self.tab_widget.setMovable(True)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_targets_tab()
        self.create_results_tab()
        self.create_reports_tab()
        self.create_settings_tab()
        
        layout.addWidget(self.tab_widget)
    
    def create_dashboard_tab(self):
        """Create dashboard overview tab"""
        self.dashboard_widget = DashboardWidget(self.config_manager)
        self.tab_widget.addTab(self.dashboard_widget, "🏠 Dashboard")
    
    def create_scan_tab(self):
        """Create scan configuration tab"""
        scan_widget = QWidget()
        layout = QHBoxLayout(scan_widget)
        
        # Left side - Scan configuration
        config_group = QGroupBox("Scan Configuration")
        config_layout = QVBoxLayout(config_group)
        
        # Target input
        target_frame = QFrame()
        target_layout = QHBoxLayout(target_frame)
        target_layout.addWidget(QLabel("Target:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter target URL or IP address")
        target_layout.addWidget(self.target_input)
        config_layout.addWidget(target_frame)
        
        # Scan profile selection
        profile_frame = QFrame()
        profile_layout = QHBoxLayout(profile_frame)
        profile_layout.addWidget(QLabel("Profile:"))
        self.profile_combo = QComboBox()
        self.load_scan_profiles()
        profile_layout.addWidget(self.profile_combo)
        config_layout.addWidget(profile_frame)
        
        # Tool selection
        tools_group = QGroupBox("Security Tools")
        tools_layout = QGridLayout(tools_group)
        
        self.tool_checkboxes = {}
        tools = ['nmap', 'nuclei', 'nikto', 'dirb', 'sqlmap', 'wapiti', 'gvm']
        for i, tool in enumerate(tools):
            checkbox = QCheckBox(tool.upper())
            checkbox.setChecked(self.config_manager.is_tool_enabled(tool))
            self.tool_checkboxes[tool] = checkbox
            tools_layout.addWidget(checkbox, i // 3, i % 3)
        
        config_layout.addWidget(tools_group)
        
        # Scan options
        options_group = QGroupBox("Scan Options")
        options_layout = QGridLayout(options_group)
        
        options_layout.addWidget(QLabel("Threads:"), 0, 0)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 50)
        self.threads_spin.setValue(10)
        options_layout.addWidget(self.threads_spin, 0, 1)
        
        options_layout.addWidget(QLabel("Timeout (s):"), 1, 0)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(5, 3600)
        self.timeout_spin.setValue(300)
        options_layout.addWidget(self.timeout_spin, 1, 1)
        
        self.aggressive_scan = QCheckBox("Aggressive Scan")
        options_layout.addWidget(self.aggressive_scan, 2, 0, 1, 2)
        
        config_layout.addWidget(options_group)
        
        # Control buttons
        button_frame = QFrame()
        button_layout = QHBoxLayout(button_frame)
        
        self.start_scan_btn = QPushButton("🚀 Start Scan")
        self.start_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #2E7D32;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #388E3C;
            }
            QPushButton:pressed {
                background-color: #1B5E20;
            }
            QPushButton:disabled {
                background-color: #555;
                color: #999;
            }
        """)
        self.start_scan_btn.clicked.connect(self.start_scan)
        button_layout.addWidget(self.start_scan_btn)
        
        self.stop_scan_btn = QPushButton("⏹ Stop Scan")
        self.stop_scan_btn.setStyleSheet("""
            QPushButton {
                background-color: #C62828;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #D32F2F;
            }
            QPushButton:pressed {
                background-color: #B71C1C;
            }
        """)
        self.stop_scan_btn.setEnabled(False)
        self.stop_scan_btn.clicked.connect(self.stop_scan)
        button_layout.addWidget(self.stop_scan_btn)
        
        button_layout.addStretch()
        config_layout.addWidget(button_frame)
        
        layout.addWidget(config_group, 1)
        
        # Right side - Live results
        results_group = QGroupBox("Live Scan Results")
        results_layout = QVBoxLayout(results_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        results_layout.addWidget(self.progress_bar)
        
        # Results tree
        self.results_tree = QTreeWidget()
        self.results_tree.setHeaderLabels(["Tool", "Finding", "Severity", "Target"])
        self.results_tree.setAlternatingRowColors(True)
        results_layout.addWidget(self.results_tree)
        
        # Status text
        self.status_text = QTextEdit()
        self.status_text.setMaximumHeight(100)
        self.status_text.setReadOnly(True)
        results_layout.addWidget(self.status_text)
        
        layout.addWidget(results_group, 2)
        
        self.tab_widget.addTab(scan_widget, "🔍 Scan")
    
    def create_targets_tab(self):
        """Create target management tab"""
        self.target_manager = TargetManagerWidget(self.config_manager)
        self.tab_widget.addTab(self.target_manager, "🎯 Targets")
    
    def create_results_tab(self):
        """Create results analysis tab"""
        self.results_widget = ResultsWidget(self.config_manager)
        self.tab_widget.addTab(self.results_widget, "📊 Results")
    
    def create_reports_tab(self):
        """Create reports tab"""
        self.report_viewer = ReportViewerWidget(self.config_manager)
        self.tab_widget.addTab(self.report_viewer, "📄 Reports")
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        
        # Tools configuration
        tools_group = QGroupBox("Tools Configuration")
        tools_layout = QVBoxLayout(tools_group)
        
        # GVM Settings
        gvm_frame = self.create_tool_config_frame("GVM/OpenVAS", "gvm")
        tools_layout.addWidget(gvm_frame)
        
        # Nuclei Settings
        nuclei_frame = self.create_tool_config_frame("Nuclei", "nuclei")
        tools_layout.addWidget(nuclei_frame)
        
        layout.addWidget(tools_group)
        layout.addStretch()
        
        self.tab_widget.addTab(settings_widget, "⚙ Settings")
    
    def create_tool_config_frame(self, tool_display_name: str, tool_key: str) -> QGroupBox:
        """Create configuration frame for a specific tool"""
        group = QGroupBox(tool_display_name)
        layout = QGridLayout(group)
        
        config = self.config_manager.get_tool_config(tool_key)
        
        # Enabled checkbox
        enabled_cb = QCheckBox("Enabled")
        enabled_cb.setChecked(config.get('enabled', False))
        layout.addWidget(enabled_cb, 0, 0, 1, 2)
        
        # Tool-specific configuration
        if tool_key == 'gvm':
            layout.addWidget(QLabel("Host:"), 1, 0)
            host_input = QLineEdit(config.get('host', '127.0.0.1'))
            layout.addWidget(host_input, 1, 1)
            
            layout.addWidget(QLabel("Port:"), 2, 0)
            port_input = QSpinBox()
            port_input.setRange(1, 65535)
            port_input.setValue(config.get('port', 9390))
            layout.addWidget(port_input, 2, 1)
        
        elif tool_key == 'nuclei':
            layout.addWidget(QLabel("Binary Path:"), 1, 0)
            binary_input = QLineEdit(config.get('binary_path', '/usr/bin/nuclei'))
            layout.addWidget(binary_input, 1, 1)
            
            layout.addWidget(QLabel("Templates Dir:"), 2, 0)
            templates_input = QLineEdit(config.get('templates_dir', ''))
            layout.addWidget(templates_input, 2, 1)
        
        return group
    
    def setup_menu_bar(self):
        """Setup application menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_project_action = QAction("New Project", self)
        new_project_action.setShortcut(QKeySequence.New)
        new_project_action.triggered.connect(self.new_project)
        file_menu.addAction(new_project_action)
        
        open_project_action = QAction("Open Project", self)
        open_project_action.setShortcut(QKeySequence.Open)
        open_project_action.triggered.connect(self.open_project)
        file_menu.addAction(open_project_action)
        
        save_project_action = QAction("Save Project", self)
        save_project_action.setShortcut(QKeySequence.Save)
        save_project_action.triggered.connect(self.save_project)
        file_menu.addAction(save_project_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        update_tools_action = QAction("Update Security Tools", self)
        update_tools_action.triggered.connect(self.update_tools)
        tools_menu.addAction(update_tools_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def setup_toolbar(self):
        """Setup main toolbar"""
        toolbar = QToolBar("Main Toolbar")
        self.addToolBar(toolbar)
        
        # Quick scan button
        quick_scan_action = QAction("Quick Scan", self)
        quick_scan_action.setToolTip("Start quick security scan")
        quick_scan_action.triggered.connect(self.quick_scan)
        toolbar.addAction(quick_scan_action)
        
        toolbar.addSeparator()
        
        # Target input in toolbar
        toolbar.addWidget(QLabel("Target: "))
        self.toolbar_target_input = QLineEdit()
        self.toolbar_target_input.setMaximumWidth(300)
        self.toolbar_target_input.setPlaceholderText("Quick target input...")
        toolbar.addWidget(self.toolbar_target_input)
    
    def setup_status_bar(self):
        """Setup status bar"""
        self.statusBar().showMessage("Ready")
        
        # Add permanent widgets to status bar
        self.status_label = QLabel("Idle")
        self.statusBar().addPermanentWidget(self.status_label)
        
        self.scan_count_label = QLabel("Scans: 0")
        self.statusBar().addPermanentWidget(self.scan_count_label)
    
    def apply_dark_theme(self):
        """Apply dark theme to the application"""
        dark_stylesheet = """
        QMainWindow {
            background-color: #2b2b2b;
            color: #ffffff;
        }
        QTabWidget::pane {
            border: 1px solid #555555;
            background-color: #2b2b2b;
        }
        QTabBar::tab {
            background-color: #3c3c3c;
            color: #ffffff;
            padding: 8px 16px;
            margin-right: 2px;
            border-top-left-radius: 4px;
            border-top-right-radius: 4px;
        }
        QTabBar::tab:selected {
            background-color: #404040;
            border-bottom: 2px solid #0078d4;
        }
        QGroupBox {
            font-weight: bold;
            border: 2px solid #555555;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
        }
        QTreeWidget {
            background-color: #353535;
            alternate-background-color: #404040;
            selection-background-color: #0078d4;
        }
        QTextEdit {
            background-color: #353535;
            border: 1px solid #555555;
        }
        QLineEdit {
            background-color: #353535;
            border: 1px solid #555555;
            padding: 4px;
            border-radius: 2px;
        }
        """
        self.setStyleSheet(dark_stylesheet)
        self.setStyleSheet(dark_stylesheet)
    
    def load_scan_profiles(self):
        """Load scan profiles into combo box"""
        profiles = self.config_manager.profiles
        self.profile_combo.clear()
        
        for profile_key, profile_data in profiles.items():
            display_name = profile_data.get('name', profile_key)
            self.profile_combo.addItem(display_name, profile_key)
    
    def start_scan(self):
        """Start security scan"""
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Warning", "Please enter a target URL or IP address")
            return
        
        profile_key = self.profile_combo.currentData()
        profile = self.config_manager.get_profile(profile_key)
        
        # Get selected tools
        selected_tools = []
        for tool, checkbox in self.tool_checkboxes.items():
            if checkbox.isChecked():
                selected_tools.append(tool)
        
        if not selected_tools:
            QMessageBox.warning(self, "Warning", "Please select at least one security tool")
            return
        
        self.logger.info(f"Starting scan of {target} with profile {profile_key}")
        self.security_logger.log_scan_start(target, "manual", profile_key)
        
        # Update UI
        self.start_scan_btn.setEnabled(False)
        self.stop_scan_btn.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        self.status_text.append(f"Starting scan of {target}...")
        self.statusBar().showMessage(f"Scanning {target}...")
        
        # TODO: Start actual scan in separate thread
        # This is a placeholder - actual scan logic will be implemented
        # in subsequent modules
    
    def stop_scan(self):
        """Stop running scan"""
        self.logger.info("Stopping scan")
        
        # Update UI
        self.start_scan_btn.setEnabled(True)
        self.stop_scan_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        self.status_text.append("Scan stopped by user")
        self.statusBar().showMessage("Ready")
    
    def quick_scan(self):
        """Start quick scan from toolbar"""
        target = self.toolbar_target_input.text().strip()
        if target:
            self.target_input.setText(target)
            self.profile_combo.setCurrentIndex(0)  # Quick scan profile
            self.start_scan()
    
    def new_project(self):
        """Create new project"""
        # TODO: Implement project management
        QMessageBox.information(self, "Info", "New project functionality coming soon")
    
    def open_project(self):
        """Open existing project"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Open Project", "", "Security Scanner Projects (*.ssp)"
        )
        if file_path:
            # TODO: Implement project loading
            self.logger.info(f"Opening project: {file_path}")
    
    def save_project(self):
        """Save current project"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Project", "", "Security Scanner Projects (*.ssp)"
        )
        if file_path:
            # TODO: Implement project saving
            self.logger.info(f"Saving project: {file_path}")
    
    def update_tools(self):
        """Update security tools"""
        QMessageBox.information(self, "Info", "Tool update functionality coming soon")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h3>Advanced Security Scanner v1.0</h3>
        <p>Comprehensive security testing platform integrating:</p>
        <ul>
        <li>GVM/OpenVAS - Vulnerability Assessment</li>
        <li>Nuclei - Fast vulnerability scanner</li>
        <li>OWASP WSTG - Web security testing</li>
        <li>50+ Security Tools Integration</li>
        </ul>
        <p><b>Features:</b></p>
        <ul>
        <li>Multi-threaded scanning</li>
        <li>Comprehensive reporting</li>
        <li>API testing capabilities</li>
        <li>Real-time results</li>
        </ul>
        """
        QMessageBox.about(self, "About Advanced Security Scanner", about_text)
    
    def load_window_settings(self):
        """Load window geometry and state"""
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        window_state = self.settings.value("windowState")
        if window_state:
            self.restoreState(window_state)
    
    def save_window_settings(self):
        """Save window geometry and state"""
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
    
    def closeEvent(self, event):
        """Handle application close event"""
        self.save_window_settings()
        self.logger.info("Application closing")
        super().closeEvent(event)
