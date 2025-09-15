"""
Configuration Manager for Advanced Security Scanner
"""

import json
import yaml
import os
from pathlib import Path
from typing import Dict, Any, Optional
import logging

class ConfigManager:
    """Manages configuration for the security scanner"""
    
    def __init__(self, config_dir: Optional[Path] = None):
        self.logger = logging.getLogger(__name__)
        
        # Set config directory
        if config_dir is None:
            config_dir = Path.home() / ".security_scanner"
        
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(exist_ok=True)
        
        # Config files
        self.main_config_file = self.config_dir / "config.yaml"
        self.tools_config_file = self.config_dir / "tools.yaml"
        self.profiles_config_file = self.config_dir / "profiles.yaml"
        
        # Load configurations
        self.config = self._load_config()
        self.tools_config = self._load_tools_config()
        self.profiles = self._load_profiles_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load main configuration"""
        default_config = {
            "gui": {
                "theme": "dark",
                "auto_save": True,
                "max_concurrent_scans": 5,
                "update_interval": 1000
            },
            "logging": {
                "level": "INFO",
                "max_files": 10,
                "max_size_mb": 10
            },
            "database": {
                "path": str(self.config_dir / "scanner.db"),
                "backup_enabled": True,
                "backup_interval_hours": 24
            },
            "reports": {
                "default_format": "html",
                "auto_generate": True,
                "include_screenshots": True
            }
        }
        
        if self.main_config_file.exists():
            try:
                with open(self.main_config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    # Merge with defaults
                    return {**default_config, **config}
            except Exception as e:
                self.logger.error(f"Error loading main config: {e}")
                return default_config
        else:
            self.save_config(default_config)
            return default_config
    
    def _load_tools_config(self) -> Dict[str, Any]:
        """Load tools configuration"""
        default_tools = {
            "gvm": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 9390,
                "username": "",
                "password": "",
                "socket_path": "/var/run/gvm/gvmd.sock"
            },
            "nuclei": {
                "enabled": True,
                "binary_path": "/usr/bin/nuclei",
                "templates_dir": "/home/mans/nuclei-templates",
                "update_templates": True,
                "rate_limit": 150,
                "bulk_size": 25,
                "timeout": 10
            },
            "nmap": {
                "enabled": True,
                "binary_path": "/usr/bin/nmap",
                "default_ports": "1-65535",
                "timing": "T4",
                "max_retries": 2
            },
            "nikto": {
                "enabled": True,
                "binary_path": "/usr/bin/nikto",
                "config_file": "/etc/nikto.conf"
            },
            "sqlmap": {
                "enabled": True,
                "binary_path": "/usr/bin/sqlmap",
                "timeout": 30,
                "risk": 1,
                "level": 1
            },
            "dirb": {
                "enabled": True,
                "binary_path": "/usr/bin/dirb",
                "wordlist": "/usr/share/dirb/wordlists/common.txt"
            },
            "wapiti": {
                "enabled": True,
                "binary_path": "/usr/bin/wapiti",
                "modules": "all",
                "level": 1
            },
            "zaproxy": {
                "enabled": False,
                "api_key": "",
                "proxy_host": "127.0.0.1",
                "proxy_port": 8080
            },
            "burp": {
                "enabled": False,
                "api_key": "",
                "api_url": "http://127.0.0.1:1337"
            }
        }
        
        if self.tools_config_file.exists():
            try:
                with open(self.tools_config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    return {**default_tools, **config}
            except Exception as e:
                self.logger.error(f"Error loading tools config: {e}")
                return default_tools
        else:
            self.save_tools_config(default_tools)
            return default_tools
    
    def _load_profiles_config(self) -> Dict[str, Any]:
        """Load scanning profiles configuration"""
        default_profiles = {
            "quick_scan": {
                "name": "Quick Scan",
                "description": "Basic security scan with minimal time",
                "tools": ["nmap", "nuclei"],
                "nmap_options": "-sS -T4 --top-ports 1000",
                "nuclei_templates": ["cves", "exposed-panels", "technologies"],
                "timeout": 300
            },
            "full_scan": {
                "name": "Full Security Scan", 
                "description": "Comprehensive security assessment",
                "tools": ["nmap", "nuclei", "nikto", "dirb", "wapiti"],
                "nmap_options": "-sS -sV -O -T4 -p1-65535",
                "nuclei_templates": ["cves", "exposed-panels", "technologies", "vulnerabilities", "misconfiguration"],
                "timeout": 3600
            },
            "web_app_scan": {
                "name": "Web Application Scan",
                "description": "OWASP WSTG focused scan",
                "tools": ["nuclei", "nikto", "dirb", "sqlmap", "wapiti"],
                "wstg_tests": "all",
                "timeout": 1800
            },
            "api_scan": {
                "name": "API Security Scan",
                "description": "REST/GraphQL API testing",
                "tools": ["nuclei"],
                "api_tests": ["authentication", "authorization", "injection", "rate_limiting"],
                "timeout": 900
            },
            "network_scan": {
                "name": "Network Infrastructure Scan",
                "description": "Network services and infrastructure testing",
                "tools": ["nmap", "nuclei"],
                "nmap_options": "-sS -sV -O -sC -T4",
                "nuclei_templates": ["network", "services", "protocols"],
                "timeout": 1200
            }
        }
        
        if self.profiles_config_file.exists():
            try:
                with open(self.profiles_config_file, 'r') as f:
                    config = yaml.safe_load(f)
                    return {**default_profiles, **config}
            except Exception as e:
                self.logger.error(f"Error loading profiles config: {e}")
                return default_profiles
        else:
            self.save_profiles_config(default_profiles)
            return default_profiles
    
    def save_config(self, config: Optional[Dict[str, Any]] = None):
        """Save main configuration"""
        if config is None:
            config = self.config
        
        try:
            with open(self.main_config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            self.config = config
            self.logger.info("Main configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving main config: {e}")
    
    def save_tools_config(self, config: Optional[Dict[str, Any]] = None):
        """Save tools configuration"""
        if config is None:
            config = self.tools_config
            
        try:
            with open(self.tools_config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            self.tools_config = config
            self.logger.info("Tools configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving tools config: {e}")
    
    def save_profiles_config(self, config: Optional[Dict[str, Any]] = None):
        """Save profiles configuration"""
        if config is None:
            config = self.profiles
            
        try:
            with open(self.profiles_config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            self.profiles = config
            self.logger.info("Profiles configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Error saving profiles config: {e}")
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for specific tool"""
        return self.tools_config.get(tool_name, {})
    
    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """Get specific scanning profile"""
        return self.profiles.get(profile_name, {})
    
    def get_config_value(self, key_path: str, default=None):
        """Get configuration value using dot notation (e.g., 'gui.theme')"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set_config_value(self, key_path: str, value: Any):
        """Set configuration value using dot notation"""
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set value
        config[keys[-1]] = value
        self.save_config()
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled"""
        return self.tools_config.get(tool_name, {}).get('enabled', False)
    
    def set_config(self, section: str, key: str, value: Any):
        """Set configuration value in a section"""
        if section not in self.config:
            self.config[section] = {}
        self.config[section][key] = value
        self.save_config()
    
    def get_config(self, section: str, key: str, default=None):
        """Get configuration value from a section"""
        return self.config.get(section, {}).get(key, default)
    
    def set_tool_config(self, tool_name: str, key: str, value: Any):
        """Set tool configuration value"""
        if tool_name not in self.tools_config:
            self.tools_config[tool_name] = {}
        self.tools_config[tool_name][key] = value
        self.save_tools_config()
    
    def get_all_profiles(self) -> Dict[str, Any]:
        """Get all available profiles"""
        return self.profiles.copy()
    
    def get_all_tools(self) -> Dict[str, Any]:
        """Get all tool configurations"""
        return self.tools_config.copy()
