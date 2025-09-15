#!/usr/bin/env python3
"""
Advanced Security Scanner with GUI
Integrates GVM, Nuclei, OWASP WSTG, and 50+ security tools

Author: ReliableSecurity
GitHub: https://github.com/ReliableSecurity
Telegram: @ReliableSecurity
"""

import sys
import os
import logging
import asyncio
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

from gui.main_window import SecurityScannerMainWindow
from core.config_manager import ConfigManager
from core.logger import setup_logging

def main():
    """Main application entry point"""
    
    # Setup logging
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    setup_logging(log_dir / "scanner.log")
    
    logger = logging.getLogger(__name__)
    logger.info("Starting Advanced Security Scanner")
    
    # Initialize configuration
    config_manager = ConfigManager()
    
    # Auto-update vulnerability database on startup
    try:
        from intelligence.vulnerability_updater import auto_update_on_startup
        logger.info("Checking for vulnerability database updates...")
        asyncio.run(auto_update_on_startup())
    except Exception as e:
        logger.warning(f"Auto-update failed, continuing: {e}")
    
    # Create QApplication
    app = QApplication(sys.argv)
    app.setApplicationName("Advanced Security Scanner")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("SecurityTools")
    
    # Enable high DPI support
    if hasattr(Qt, 'AA_EnableHighDpiScaling'):
        app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    
    if hasattr(Qt, 'AA_UseHighDpiPixmaps'):
        app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    
    # Set application icon (if available)
    icon_path = Path(__file__).parent / "resources" / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    
    # Create main window
    main_window = SecurityScannerMainWindow(config_manager)
    main_window.show()
    
    logger.info("Application started successfully")
    
    # Run application
    try:
        return app.exec_()
    except Exception as e:
        logger.error(f"Application error: {e}", exc_info=True)
        return 1
    finally:
        logger.info("Application shutdown")

if __name__ == "__main__":
    sys.exit(main())