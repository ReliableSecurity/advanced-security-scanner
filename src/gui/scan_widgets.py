"""
Scan Configuration and Results Widgets
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from core.config_manager import ConfigManager

class ScanConfigWidget(QWidget):
    """Widget for configuring scan parameters"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Scan Configuration Widget - Coming Soon"))

class ResultsWidget(QWidget):
    """Widget for displaying scan results"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Results Analysis Widget - Coming Soon"))