"""
Target Manager Widget
"""

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel
from core.config_manager import ConfigManager

class TargetManagerWidget(QWidget):
    """Widget for managing scan targets"""
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Target Manager Widget - Coming Soon"))