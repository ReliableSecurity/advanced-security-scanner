"""
Report Viewer Widget
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from core.config_manager import ConfigManager

class ReportViewerWidget(QWidget):
    """Widget for viewing and generating reports"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Report Viewer Widget - Coming Soon"))