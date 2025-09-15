#!/usr/bin/env python3
"""
Notification Manager
Sends alerts via Telegram, Slack, email when critical vulnerabilities are found
"""

import sys
import os
import asyncio
import json
import smtplib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import aiohttp
import hashlib

# Email imports with fallback
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
    from email.mime.base import MimeBase
    from email import encoders
    EMAIL_AVAILABLE = True
except ImportError:
    EMAIL_AVAILABLE = False
    # Create dummy classes for fallback
    class MimeText:
        def __init__(self, *args, **kwargs): pass
    class MimeMultipart:
        def __init__(self, *args, **kwargs): pass
        def attach(self, *args): pass
        def __setitem__(self, key, value): pass
    class MimeBase:
        def __init__(self, *args, **kwargs): pass

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.logger import get_security_logger
from core.config_manager import ConfigManager

class NotificationConfig:
    """Configuration for notification channels"""
    
    def __init__(self, config: Dict):
        self.enabled = config.get('enabled', False)
        self.channels = config.get('channels', {})
        self.severity_threshold = config.get('severity_threshold', 'high')
        self.rate_limit = config.get('rate_limit', 10)  # Max notifications per hour
        self.deduplicate = config.get('deduplicate', True)
        
    def get_email_config(self) -> Dict:
        return self.channels.get('email', {})
    
    def get_telegram_config(self) -> Dict:
        return self.channels.get('telegram', {})
    
    def get_slack_config(self) -> Dict:
        return self.channels.get('slack', {})

class EmailNotifier:
    """Email notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = get_security_logger("email_notifier")
        
        # SMTP settings
        self.smtp_server = config.get('smtp_server', 'localhost')
        self.smtp_port = config.get('smtp_port', 587)
        self.username = config.get('username', '')
        self.password = config.get('password', '')
        self.use_tls = config.get('use_tls', True)
        
        # Email settings
        self.from_email = config.get('from_email', 'scanner@security.local')
        self.to_emails = config.get('to_emails', [])
        
    async def send_alert(self, vulnerability: Dict, scan_info: Dict) -> bool:
        """Send email alert for vulnerability"""
        if not EMAIL_AVAILABLE:
            self.logger.warning("Email functionality not available")
            return False
            
        try:
            msg = MimeMultipart('alternative')
            msg['Subject'] = f"🚨 Critical Vulnerability Detected: {vulnerability.get('type', 'Unknown')}"
            msg['From'] = self.from_email
            msg['To'] = ', '.join(self.to_emails)
            
            # Create HTML content
            html_content = self._create_html_content(vulnerability, scan_info)
            html_part = MimeText(html_content, 'html')
            
            # Create text content
            text_content = self._create_text_content(vulnerability, scan_info)
            text_part = MimeText(text_content, 'plain')
            
            msg.attach(text_part)
            msg.attach(html_part)
            
            # Send email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            if self.use_tls:
                server.starttls()
            
            if self.username and self.password:
                server.login(self.username, self.password)
            
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for vulnerability: {vulnerability.get('id')}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {e}")
            return False
    
    def _create_html_content(self, vulnerability: Dict, scan_info: Dict) -> str:
        """Create HTML email content"""
        severity = vulnerability.get('severity', 'unknown').upper()
        severity_color = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14', 
            'MEDIUM': '#ffc107',
            'LOW': '#28a745'
        }.get(severity, '#6c757d')
        
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                          color: white; padding: 20px; text-align: center; }}
                .content {{ padding: 20px; background: #f8f9fa; }}
                .vulnerability-card {{ background: white; border-left: 4px solid {severity_color}; 
                                    padding: 15px; margin: 10px 0; border-radius: 4px; }}
                .severity {{ background: {severity_color}; color: white; padding: 5px 10px; 
                           border-radius: 20px; font-size: 0.8em; }}
                .details {{ margin: 15px 0; }}
                .footer {{ text-align: center; margin-top: 30px; color: #6c757d; }}
                table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                td {{ padding: 8px; border: 1px solid #ddd; }}
                th {{ background: #e9ecef; padding: 8px; border: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 Security Scanner Alert</h1>
                <p>Critical vulnerability detected during security scan</p>
            </div>
            
            <div class="content">
                <div class="vulnerability-card">
                    <h2>{vulnerability.get('title', 'Unknown Vulnerability')} 
                        <span class="severity">{severity}</span></h2>
                    
                    <div class="details">
                        <table>
                            <tr><th>Target</th><td>{vulnerability.get('target', 'Unknown')}</td></tr>
                            <tr><th>Type</th><td>{vulnerability.get('type', 'Unknown')}</td></tr>
                            <tr><th>CVSS Score</th><td>{vulnerability.get('cvss_score', 'N/A')}</td></tr>
                            <tr><th>CVE</th><td>{vulnerability.get('cve_id', 'N/A')}</td></tr>
                            <tr><th>Tool</th><td>{vulnerability.get('tool', 'Unknown')}</td></tr>
                            <tr><th>Detected</th><td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>
                        </table>
                        
                        <h3>Description</h3>
                        <p>{vulnerability.get('description', 'No description available.')}</p>
                        
                        {self._format_exploits(vulnerability.get('exploits', []))}
                        {self._format_recommendations(vulnerability.get('recommendations', []))}
                    </div>
                </div>
                
                <div class="scan-info">
                    <h3>Scan Information</h3>
                    <table>
                        <tr><th>Scan ID</th><td>{scan_info.get('scan_id', 'Unknown')}</td></tr>
                        <tr><th>Profile</th><td>{scan_info.get('profile', 'Unknown')}</td></tr>
                        <tr><th>Started</th><td>{scan_info.get('started_at', 'Unknown')}</td></tr>
                        <tr><th>Total Vulnerabilities</th><td>{scan_info.get('vulnerabilities_found', 0)}</td></tr>
                    </table>
                </div>
            </div>
            
            <div class="footer">
                <p>This alert was generated by Advanced Security Scanner v2.0</p>
                <p>Take immediate action to remediate critical vulnerabilities</p>
            </div>
        </body>
        </html>
        """
    
    def _create_text_content(self, vulnerability: Dict, scan_info: Dict) -> str:
        """Create plain text email content"""
        return f"""
🚨 SECURITY ALERT - Critical Vulnerability Detected

VULNERABILITY DETAILS:
Title: {vulnerability.get('title', 'Unknown')}
Type: {vulnerability.get('type', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown').upper()}
Target: {vulnerability.get('target', 'Unknown')}
CVSS Score: {vulnerability.get('cvss_score', 'N/A')}
CVE: {vulnerability.get('cve_id', 'N/A')}
Tool: {vulnerability.get('tool', 'Unknown')}
Detected: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC

DESCRIPTION:
{vulnerability.get('description', 'No description available.')}

SCAN INFORMATION:
Scan ID: {scan_info.get('scan_id', 'Unknown')}
Profile: {scan_info.get('profile', 'Unknown')}  
Started: {scan_info.get('started_at', 'Unknown')}
Total Vulnerabilities: {scan_info.get('vulnerabilities_found', 0)}

⚠️  IMMEDIATE ACTION REQUIRED
Please review and remediate this vulnerability as soon as possible.

---
Advanced Security Scanner v2.0
        """
    
    def _format_exploits(self, exploits: List[Dict]) -> str:
        """Format exploits section"""
        if not exploits:
            return ""
        
        html = "<h3>⚠️ Available Exploits</h3><ul>"
        for exploit in exploits[:3]:  # Show first 3 exploits
            html += f"<li><strong>{exploit.get('title', 'Unknown')}</strong> "
            html += f"(EDB-{exploit.get('edb_id', 'Unknown')})</li>"
        html += "</ul>"
        
        if len(exploits) > 3:
            html += f"<p><em>... and {len(exploits) - 3} more exploits available</em></p>"
        
        return html
    
    def _format_recommendations(self, recommendations: List[str]) -> str:
        """Format recommendations section"""
        if not recommendations:
            return ""
        
        html = "<h3>🔧 Recommendations</h3><ul>"
        for rec in recommendations[:3]:
            html += f"<li>{rec}</li>"
        html += "</ul>"
        
        return html

class TelegramNotifier:
    """Telegram notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = get_security_logger("telegram_notifier")
        
        self.bot_token = config.get('bot_token', '')
        self.chat_ids = config.get('chat_ids', [])
        self.parse_mode = config.get('parse_mode', 'HTML')
        
    async def send_alert(self, vulnerability: Dict, scan_info: Dict) -> bool:
        """Send Telegram alert"""
        if not self.bot_token or not self.chat_ids:
            self.logger.warning("Telegram not configured properly")
            return False
        
        try:
            message = self._create_telegram_message(vulnerability, scan_info)
            
            async with aiohttp.ClientSession() as session:
                for chat_id in self.chat_ids:
                    url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
                    
                    payload = {
                        'chat_id': chat_id,
                        'text': message,
                        'parse_mode': self.parse_mode,
                        'disable_web_page_preview': True
                    }
                    
                    async with session.post(url, json=payload) as response:
                        if response.status == 200:
                            self.logger.info(f"Telegram alert sent to chat {chat_id}")
                        else:
                            self.logger.error(f"Failed to send Telegram alert: {response.status}")
                            return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send Telegram alert: {e}")
            return False
    
    def _create_telegram_message(self, vulnerability: Dict, scan_info: Dict) -> str:
        """Create Telegram message"""
        severity = vulnerability.get('severity', 'unknown').upper()
        severity_emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢'
        }.get(severity, '⚪')
        
        message = f"""
🚨 <b>Security Alert</b> 🚨

{severity_emoji} <b>{vulnerability.get('title', 'Unknown Vulnerability')}</b>

<b>Details:</b>
• Target: <code>{vulnerability.get('target', 'Unknown')}</code>
• Type: {vulnerability.get('type', 'Unknown')}
• Severity: <b>{severity}</b>
• CVSS: {vulnerability.get('cvss_score', 'N/A')}
• CVE: {vulnerability.get('cve_id', 'N/A')}
• Tool: {vulnerability.get('tool', 'Unknown')}

<b>Description:</b>
{vulnerability.get('description', 'No description available.')[:200]}...

<b>Scan Info:</b>
• ID: <code>{scan_info.get('scan_id', 'Unknown')}</code>
• Profile: {scan_info.get('profile', 'Unknown')}
• Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
"""
        
        if vulnerability.get('exploits'):
            message += f"\n⚠️ <b>{len(vulnerability['exploits'])} exploit(s) available!</b>"
        
        message += "\n\n🔧 <b>Action Required:</b> Review and remediate immediately"
        
        return message

class SlackNotifier:
    """Slack notification handler"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.logger = get_security_logger("slack_notifier")
        
        self.webhook_url = config.get('webhook_url', '')
        self.channel = config.get('channel', '#security')
        self.username = config.get('username', 'Security Scanner')
        self.icon_emoji = config.get('icon_emoji', ':warning:')
        
    async def send_alert(self, vulnerability: Dict, scan_info: Dict) -> bool:
        """Send Slack alert"""
        if not self.webhook_url:
            self.logger.warning("Slack webhook URL not configured")
            return False
        
        try:
            payload = self._create_slack_payload(vulnerability, scan_info)
            
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as response:
                    if response.status == 200:
                        self.logger.info("Slack alert sent successfully")
                        return True
                    else:
                        self.logger.error(f"Failed to send Slack alert: {response.status}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {e}")
            return False
    
    def _create_slack_payload(self, vulnerability: Dict, scan_info: Dict) -> Dict:
        """Create Slack message payload"""
        severity = vulnerability.get('severity', 'unknown').upper()
        severity_color = {
            'CRITICAL': 'danger',
            'HIGH': 'warning',
            'MEDIUM': 'warning',
            'LOW': 'good'
        }.get(severity, '#808080')
        
        return {
            "channel": self.channel,
            "username": self.username,
            "icon_emoji": self.icon_emoji,
            "attachments": [{
                "color": severity_color,
                "title": f"🚨 Critical Vulnerability Detected",
                "title_link": f"http://localhost:8000/scan/{scan_info.get('scan_id')}",
                "text": vulnerability.get('description', 'No description available.')[:300],
                "fields": [
                    {
                        "title": "Target",
                        "value": vulnerability.get('target', 'Unknown'),
                        "short": True
                    },
                    {
                        "title": "Severity", 
                        "value": severity,
                        "short": True
                    },
                    {
                        "title": "Type",
                        "value": vulnerability.get('type', 'Unknown'),
                        "short": True
                    },
                    {
                        "title": "CVSS Score",
                        "value": str(vulnerability.get('cvss_score', 'N/A')),
                        "short": True
                    },
                    {
                        "title": "CVE",
                        "value": vulnerability.get('cve_id', 'N/A'),
                        "short": True
                    },
                    {
                        "title": "Tool",
                        "value": vulnerability.get('tool', 'Unknown'),
                        "short": True
                    }
                ],
                "footer": "Advanced Security Scanner",
                "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png",
                "ts": int(datetime.utcnow().timestamp())
            }]
        }

class NotificationManager:
    """Main notification manager"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger("notification_manager")
        
        # Load notification configuration
        notification_config = config_manager.config.get('notifications', {})
        self.notification_config = NotificationConfig(notification_config)
        
        # Initialize notifiers
        self.email_notifier = None
        self.telegram_notifier = None
        self.slack_notifier = None
        
        self._init_notifiers()
        
        # Rate limiting and deduplication
        self.notification_history = []
        self.sent_notifications = {}  # For deduplication
        
    def _init_notifiers(self):
        """Initialize notification channels"""
        try:
            email_config = self.notification_config.get_email_config()
            if email_config.get('enabled', False):
                self.email_notifier = EmailNotifier(email_config)
                self.logger.info("Email notifier initialized")
            
            telegram_config = self.notification_config.get_telegram_config()
            if telegram_config.get('enabled', False):
                self.telegram_notifier = TelegramNotifier(telegram_config)
                self.logger.info("Telegram notifier initialized")
            
            slack_config = self.notification_config.get_slack_config()
            if slack_config.get('enabled', False):
                self.slack_notifier = SlackNotifier(slack_config)
                self.logger.info("Slack notifier initialized")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize notifiers: {e}")
    
    async def send_vulnerability_alert(self, vulnerability: Dict, scan_info: Dict) -> bool:
        """Send vulnerability alert through configured channels"""
        if not self.notification_config.enabled:
            return False
        
        # Check severity threshold
        if not self._meets_severity_threshold(vulnerability):
            self.logger.debug(f"Vulnerability {vulnerability.get('id')} below threshold")
            return False
        
        # Check rate limiting
        if not self._check_rate_limit():
            self.logger.warning("Notification rate limit exceeded")
            return False
        
        # Check for duplicates
        if self.notification_config.deduplicate and self._is_duplicate(vulnerability):
            self.logger.debug(f"Duplicate vulnerability {vulnerability.get('id')} ignored")
            return False
        
        success = False
        
        try:
            # Send through all configured channels
            if self.email_notifier:
                if await self.email_notifier.send_alert(vulnerability, scan_info):
                    success = True
            
            if self.telegram_notifier:
                if await self.telegram_notifier.send_alert(vulnerability, scan_info):
                    success = True
            
            if self.slack_notifier:
                if await self.slack_notifier.send_alert(vulnerability, scan_info):
                    success = True
            
            if success:
                self._record_notification(vulnerability)
                self.logger.info(f"Alert sent for vulnerability: {vulnerability.get('id')}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to send vulnerability alert: {e}")
            return False
    
    def _meets_severity_threshold(self, vulnerability: Dict) -> bool:
        """Check if vulnerability meets severity threshold"""
        severity_levels = {
            'low': 1,
            'medium': 2,  
            'high': 3,
            'critical': 4
        }
        
        vuln_severity = vulnerability.get('severity', 'low').lower()
        threshold_severity = self.notification_config.severity_threshold.lower()
        
        vuln_level = severity_levels.get(vuln_severity, 1)
        threshold_level = severity_levels.get(threshold_severity, 3)
        
        return vuln_level >= threshold_level
    
    def _check_rate_limit(self) -> bool:
        """Check notification rate limit"""
        current_time = datetime.utcnow()
        one_hour_ago = current_time - timedelta(hours=1)
        
        # Clean old notifications
        self.notification_history = [
            timestamp for timestamp in self.notification_history 
            if timestamp > one_hour_ago
        ]
        
        # Check if under limit
        if len(self.notification_history) >= self.notification_config.rate_limit:
            return False
        
        return True
    
    def _is_duplicate(self, vulnerability: Dict) -> bool:
        """Check if vulnerability is duplicate"""
        # Create hash of vulnerability characteristics
        vuln_hash = self._get_vulnerability_hash(vulnerability)
        
        # Check if sent in last 24 hours
        current_time = datetime.utcnow()
        if vuln_hash in self.sent_notifications:
            last_sent = self.sent_notifications[vuln_hash]
            if (current_time - last_sent).total_seconds() < 86400:  # 24 hours
                return True
        
        return False
    
    def _get_vulnerability_hash(self, vulnerability: Dict) -> str:
        """Generate hash for vulnerability deduplication"""
        vuln_string = f"{vulnerability.get('target')}|{vulnerability.get('type')}|{vulnerability.get('title')}"
        return hashlib.md5(vuln_string.encode()).hexdigest()
    
    def _record_notification(self, vulnerability: Dict):
        """Record sent notification"""
        current_time = datetime.utcnow()
        
        # Add to history for rate limiting
        self.notification_history.append(current_time)
        
        # Add to sent notifications for deduplication
        vuln_hash = self._get_vulnerability_hash(vulnerability)
        self.sent_notifications[vuln_hash] = current_time
    
    async def send_scan_summary(self, scan_info: Dict, vulnerabilities: List[Dict]) -> bool:
        """Send scan completion summary"""
        try:
            if not self.notification_config.enabled:
                return False
            
            # Only send summary for scans with critical/high vulnerabilities
            critical_high = [
                v for v in vulnerabilities 
                if v.get('severity', '').lower() in ['critical', 'high']
            ]
            
            if not critical_high:
                return False
            
            summary_data = {
                'id': f"summary-{scan_info.get('scan_id')}",
                'type': 'Scan Summary',
                'severity': 'high',
                'title': f"Scan completed: {len(critical_high)} critical/high vulnerabilities found",
                'description': f"Security scan of {scan_info.get('target')} completed with {len(vulnerabilities)} total vulnerabilities.",
                'target': scan_info.get('target'),
                'tool': 'Security Scanner',
                'vulnerabilities_found': len(vulnerabilities),
                'critical_high_count': len(critical_high)
            }
            
            return await self.send_vulnerability_alert(summary_data, scan_info)
            
        except Exception as e:
            self.logger.error(f"Failed to send scan summary: {e}")
            return False

# Example configuration
def create_sample_config():
    """Create sample notification configuration"""
    return {
        'notifications': {
            'enabled': True,
            'severity_threshold': 'high',
            'rate_limit': 10,
            'deduplicate': True,
            'channels': {
                'email': {
                    'enabled': True,
                    'smtp_server': 'smtp.gmail.com',
                    'smtp_port': 587,
                    'username': 'your-email@gmail.com',
                    'password': 'your-app-password',
                    'use_tls': True,
                    'from_email': 'security-scanner@company.com',
                    'to_emails': ['admin@company.com', 'security-team@company.com']
                },
                'telegram': {
                    'enabled': True,
                    'bot_token': 'YOUR_BOT_TOKEN',
                    'chat_ids': ['@security_channel', '-1001234567890'],
                    'parse_mode': 'HTML'
                },
                'slack': {
                    'enabled': True,
                    'webhook_url': 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK',
                    'channel': '#security-alerts',
                    'username': 'Security Scanner',
                    'icon_emoji': ':warning:'
                }
            }
        }
    }

# Test the notification system
async def test_notifications():
    """Test notification system"""
    config = ConfigManager()
    
    # Add sample config (in real usage, this would be in config files)
    config.config.update(create_sample_config())
    
    notification_manager = NotificationManager(config)
    
    # Test vulnerability
    test_vulnerability = {
        'id': 'test-vuln-1',
        'type': 'SQL Injection',
        'severity': 'critical',
        'title': 'Critical SQL injection in login form',
        'description': 'A critical SQL injection vulnerability was found that allows attackers to bypass authentication.',
        'target': 'example.com',
        'cvss_score': 9.8,
        'cve_id': 'CVE-2024-TEST',
        'tool': 'SQLMap',
        'exploits': [
            {'title': 'Test Exploit', 'edb_id': 12345}
        ]
    }
    
    # Test scan info
    scan_info = {
        'scan_id': 'test-scan-123',
        'target': 'example.com',
        'profile': 'comprehensive',
        'started_at': datetime.utcnow().isoformat(),
        'vulnerabilities_found': 5
    }
    
    # Send test notification
    success = await notification_manager.send_vulnerability_alert(test_vulnerability, scan_info)
    print(f"Test notification sent: {success}")

if __name__ == "__main__":
    asyncio.run(test_notifications())