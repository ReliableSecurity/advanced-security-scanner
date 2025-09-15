"""
Logging configuration for Advanced Security Scanner
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional
import colorlog

def setup_logging(log_file: Optional[str] = None, log_level: str = "INFO"):
    """
    Set up logging configuration for the application
    
    Args:
        log_file: Path to log file (optional, can be string or Path)
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler with colors
    console_handler = colorlog.StreamHandler()
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s - %(name)s - %(levelname)s%(reset)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(numeric_level)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    root_logger.addHandler(console_handler)
    
    # File handler if log file specified
    if log_file:
        log_file_path = Path(log_file) if isinstance(log_file, str) else log_file
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            str(log_file_path),
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(numeric_level)
        root_logger.addHandler(file_handler)
    
    # Set specific loggers levels
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('PyQt5').setLevel(logging.WARNING)
    
    logger = logging.getLogger(__name__)
    logger.info("Logging system initialized")

class SecurityLogger:
    """Security-focused logger with special formatting for security events"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.security_logger = logging.getLogger(f"{name}.security")
    
    # Standard logging methods
    def debug(self, message: str):
        """Log debug message"""
        self.logger.debug(message)
    
    def info(self, message: str):
        """Log info message"""
        self.logger.info(message)
    
    def warning(self, message: str):
        """Log warning message"""
        self.logger.warning(message)
    
    def error(self, message: str, exc_info=None):
        """Log error message"""
        self.logger.error(message, exc_info=exc_info)
    
    def critical(self, message: str):
        """Log critical message"""
        self.logger.critical(message)
    
    def log_scan_start(self, target: str, scan_type: str, profile: str):
        """Log scan initiation"""
        self.security_logger.info(f"SCAN_START: {scan_type} scan of {target} using profile '{profile}'")
    
    def log_scan_complete(self, target: str, scan_type: str, duration: float, findings: int):
        """Log scan completion"""
        self.security_logger.info(
            f"SCAN_COMPLETE: {scan_type} scan of {target} completed in {duration:.2f}s, "
            f"{findings} findings"
        )
    
    def log_vulnerability_found(self, target: str, vuln_type: str, severity: str, details: str):
        """Log vulnerability discovery"""
        self.security_logger.warning(
            f"VULNERABILITY: {severity} - {vuln_type} found on {target} - {details}"
        )
    
    def log_tool_execution(self, tool: str, command: str, exit_code: int):
        """Log tool execution"""
        level = logging.INFO if exit_code == 0 else logging.WARNING
        self.security_logger.log(
            level, f"TOOL_EXEC: {tool} - exit_code: {exit_code} - cmd: {command}"
        )
    
    def log_error(self, message: str, exception: Optional[Exception] = None):
        """Log error with optional exception details"""
        if exception:
            self.security_logger.error(f"ERROR: {message}", exc_info=exception)
        else:
            self.security_logger.error(f"ERROR: {message}")
    
    def log_authentication(self, service: str, success: bool, username: str = ""):
        """Log authentication attempts"""
        status = "SUCCESS" if success else "FAILURE"
        user_info = f" for user '{username}'" if username else ""
        self.security_logger.info(f"AUTH_{status}: {service}{user_info}")
    
    def log_network_activity(self, source: str, destination: str, action: str):
        """Log network-related activities"""
        self.security_logger.info(f"NETWORK: {action} from {source} to {destination}")

def get_security_logger(name: str) -> SecurityLogger:
    """Get a security logger instance"""
    return SecurityLogger(name)