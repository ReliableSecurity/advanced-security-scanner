"""
Dashboard Widget for Security Scanner
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QGroupBox, QLabel, QPushButton, QFrame, QScrollArea,
    QProgressBar, QTableWidget, QTableWidgetItem,
    QSizePolicy
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor

from core.config_manager import ConfigManager

class StatsCard(QFrame):
    """Statistics card widget"""
    
    def __init__(self, title: str, value: str, color: str = "#0078d4"):
        super().__init__()
        self.setFrameStyle(QFrame.Box)
        self.setStyleSheet(f"""
            QFrame {{
                border: 1px solid #555;
                border-radius: 8px;
                background-color: #353535;
                margin: 4px;
            }}
            QLabel {{
                border: none;
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        
        # Title
        title_label = QLabel(title)
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(f"color: #999; font-size: 11px;")
        layout.addWidget(title_label)
        
        # Value
        self.value_label = QLabel(value)
        self.value_label.setAlignment(Qt.AlignCenter)
        self.value_label.setStyleSheet(f"color: {color}; font-size: 24px; font-weight: bold;")
        layout.addWidget(self.value_label)
        
        self.setFixedSize(120, 80)
    
    def update_value(self, value: str):
        """Update the displayed value"""
        self.value_label.setText(value)

class RecentScansWidget(QWidget):
    """Widget showing recent scan results"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Recent Scans")
        header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 8px;")
        layout.addWidget(header)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Target", "Profile", "Status", "Findings", "Date"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        
        # Sample data
        self.load_recent_scans()
        
        layout.addWidget(self.table)
    
    def load_recent_scans(self):
        """Load recent scan data (placeholder)"""
        sample_data = [
            ("example.com", "Full Scan", "Completed", "15", "2 hours ago"),
            ("192.168.1.1", "Quick Scan", "Completed", "3", "1 day ago"),
            ("api.test.com", "API Scan", "Running", "-", "5 minutes ago"),
        ]
        
        self.table.setRowCount(len(sample_data))
        
        for row, data in enumerate(sample_data):
            for col, value in enumerate(data):
                item = QTableWidgetItem(str(value))
                item.setFlags(Qt.ItemIsSelectable | Qt.ItemIsEnabled)
                
                # Color code status
                if col == 2:  # Status column
                    if value == "Completed":
                        item.setForeground(QColor("#2E7D32"))
                    elif value == "Running":
                        item.setForeground(QColor("#FF9800"))
                    elif value == "Failed":
                        item.setForeground(QColor("#C62828"))
                
                self.table.setItem(row, col, item)

class QuickActionsWidget(QWidget):
    """Widget with quick action buttons"""
    
    scan_requested = pyqtSignal(str, str)  # target, profile
    
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("Quick Actions")
        header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 8px;")
        layout.addWidget(header)
        
        # Quick scan buttons
        self.create_quick_scan_button("🚀 Quick Web Scan", "quick_scan")
        self.create_quick_scan_button("🔍 Full Security Audit", "full_scan")
        self.create_quick_scan_button("🌐 Network Discovery", "network_scan")
        self.create_quick_scan_button("⚡ API Security Test", "api_scan")
        
        layout.addStretch()
    
    def create_quick_scan_button(self, text: str, profile: str):
        """Create a quick scan button"""
        btn = QPushButton(text)
        btn.setStyleSheet("""
            QPushButton {
                background-color: #404040;
                color: white;
                border: 1px solid #555;
                padding: 12px;
                border-radius: 6px;
                text-align: left;
                margin: 2px 0px;
            }
            QPushButton:hover {
                background-color: #505050;
                border-color: #0078d4;
            }
            QPushButton:pressed {
                background-color: #353535;
            }
        """)
        btn.clicked.connect(lambda: self.scan_requested.emit("", profile))
        self.layout().addWidget(btn)

class SystemStatusWidget(QWidget):
    """Widget showing system status and tool availability"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        self.init_ui()
    
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Header
        header = QLabel("System Status")
        header.setStyleSheet("font-weight: bold; font-size: 14px; margin-bottom: 8px;")
        layout.addWidget(header)
        
        # Tool status
        self.tool_status_frame = QFrame()
        self.tool_status_layout = QVBoxLayout(self.tool_status_frame)
        self.update_tool_status()
        
        layout.addWidget(self.tool_status_frame)
        layout.addStretch()
    
    def update_tool_status(self):
        """Update tool availability status"""
        tools = ['gvm', 'nuclei', 'nmap', 'nikto', 'sqlmap', 'dirb', 'wapiti']
        
        for tool in tools:
            config = self.config_manager.get_tool_config(tool)
            enabled = config.get('enabled', False)
            
            tool_frame = QFrame()
            tool_layout = QHBoxLayout(tool_frame)
            tool_layout.setContentsMargins(8, 4, 8, 4)
            
            # Tool name
            name_label = QLabel(tool.upper())
            name_label.setStyleSheet("font-weight: bold;")
            tool_layout.addWidget(name_label)
            
            tool_layout.addStretch()
            
            # Status indicator
            status_label = QLabel("●")
            if enabled:
                status_label.setStyleSheet("color: #2E7D32; font-size: 16px;")
                status_label.setToolTip("Tool enabled and available")
            else:
                status_label.setStyleSheet("color: #666; font-size: 16px;")
                status_label.setToolTip("Tool disabled or not available")
            
            tool_layout.addWidget(status_label)
            
            self.tool_status_layout.addWidget(tool_frame)

class DashboardWidget(QWidget):
    """Main dashboard widget"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        
        # Stats data
        self.stats = {
            'total_scans': 0,
            'active_scans': 0,
            'vulnerabilities': 0,
            'targets': 0
        }
        
        self.init_ui()
        self.setup_timer()
    
    def init_ui(self):
        """Initialize the dashboard UI"""
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        
        # Welcome section
        welcome_frame = QFrame()
        welcome_layout = QVBoxLayout(welcome_frame)
        
        welcome_label = QLabel("Welcome to Advanced Security Scanner")
        welcome_label.setStyleSheet("font-size: 18px; font-weight: bold; margin-bottom: 4px;")
        welcome_layout.addWidget(welcome_label)
        
        subtitle_label = QLabel("Comprehensive security testing platform")
        subtitle_label.setStyleSheet("color: #999; font-size: 14px;")
        welcome_layout.addWidget(subtitle_label)
        
        layout.addWidget(welcome_frame)
        
        # Statistics cards row
        stats_frame = QFrame()
        stats_layout = QHBoxLayout(stats_frame)
        
        self.stats_cards = {}
        
        # Total scans card
        self.stats_cards['total_scans'] = StatsCard("Total Scans", "0", "#0078d4")
        stats_layout.addWidget(self.stats_cards['total_scans'])
        
        # Active scans card
        self.stats_cards['active_scans'] = StatsCard("Active Scans", "0", "#FF9800")
        stats_layout.addWidget(self.stats_cards['active_scans'])
        
        # Vulnerabilities found card
        self.stats_cards['vulnerabilities'] = StatsCard("Vulnerabilities", "0", "#C62828")
        stats_layout.addWidget(self.stats_cards['vulnerabilities'])
        
        # Targets managed card
        self.stats_cards['targets'] = StatsCard("Targets", "0", "#2E7D32")
        stats_layout.addWidget(self.stats_cards['targets'])
        
        stats_layout.addStretch()
        layout.addWidget(stats_frame)
        
        # Main content area
        content_layout = QHBoxLayout()
        
        # Left column - Recent scans and quick actions
        left_column = QVBoxLayout()
        
        # Recent scans
        self.recent_scans_widget = RecentScansWidget()
        left_column.addWidget(self.recent_scans_widget, 2)
        
        # Quick actions
        self.quick_actions_widget = QuickActionsWidget()
        self.quick_actions_widget.scan_requested.connect(self.on_quick_scan_requested)
        left_column.addWidget(self.quick_actions_widget, 1)
        
        left_widget = QWidget()
        left_widget.setLayout(left_column)
        content_layout.addWidget(left_widget, 2)
        
        # Right column - System status and notifications
        right_column = QVBoxLayout()
        
        # System status
        self.system_status_widget = SystemStatusWidget(self.config_manager)
        right_column.addWidget(self.system_status_widget)
        
        right_widget = QWidget()
        right_widget.setLayout(right_column)
        content_layout.addWidget(right_widget, 1)
        
        content_widget = QWidget()
        content_widget.setLayout(content_layout)
        layout.addWidget(content_widget)
        
        layout.addStretch()
    
    def setup_timer(self):
        """Setup timer for periodic updates"""
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_stats)
        self.update_timer.start(5000)  # Update every 5 seconds
    
    def update_stats(self):
        """Update dashboard statistics"""
        # TODO: Get real stats from database/scan manager
        # For now, using placeholder logic
        
        self.stats_cards['total_scans'].update_value(str(self.stats['total_scans']))
        self.stats_cards['active_scans'].update_value(str(self.stats['active_scans']))
        self.stats_cards['vulnerabilities'].update_value(str(self.stats['vulnerabilities']))
        self.stats_cards['targets'].update_value(str(self.stats['targets']))
    
    def on_quick_scan_requested(self, target: str, profile: str):
        """Handle quick scan request"""
        self.logger.info(f"Quick scan requested: profile={profile}")
        # TODO: Trigger scan in main window
        # This should emit a signal to the main window to start the scan