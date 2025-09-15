"""
OWASP Web Security Testing Guide (WSTG) Core Implementation
"""

import asyncio
import logging
import requests
import urllib3
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from bs4 import BeautifulSoup
import re
import time
import ssl
import socket

from core.config_manager import ConfigManager
from core.logger import get_security_logger

# Disable SSL warnings for testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WSTGTestResult:
    """WSTG test result container"""
    
    def __init__(self, test_id: str, test_name: str, status: str = 'pending'):
        self.test_id = test_id
        self.test_name = test_name
        self.status = status  # pending, running, passed, failed, error
        self.severity = 'info'  # info, low, medium, high, critical
        self.findings = []
        self.evidence = {}
        self.recommendations = []
        self.start_time = None
        self.end_time = None
        self.error = None
    
    def add_finding(self, description: str, evidence: Dict[str, Any] = None, 
                   severity: str = 'info'):
        """Add a finding to the test result"""
        finding = {
            'description': description,
            'evidence': evidence or {},
            'severity': severity,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)
        
        # Update overall severity if this finding is more severe
        severity_levels = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if severity_levels.get(severity, 0) > severity_levels.get(self.severity, 0):
            self.severity = severity
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        duration = None
        if self.start_time and self.end_time:
            duration = (self.end_time - self.start_time).total_seconds()
        
        return {
            'test_id': self.test_id,
            'test_name': self.test_name,
            'status': self.status,
            'severity': self.severity,
            'findings': self.findings,
            'evidence': self.evidence,
            'recommendations': self.recommendations,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration': duration,
            'error': self.error
        }

class WSTGCore:
    """Core OWASP WSTG testing framework"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.security_logger = get_security_logger(__name__)
        
        # HTTP session with custom settings
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification for testing
        self.session.timeout = 30
        self.session.headers.update({
            'User-Agent': 'WSTG-Scanner/1.0 (Security Testing)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        
        # Test categories mapping
        self.test_categories = {
            'WSTG-INFO': 'Information Gathering',
            'WSTG-CONF': 'Configuration and Deployment Management Testing',
            'WSTG-IDNT': 'Identity Management Testing',
            'WSTG-ATHN': 'Authentication Testing',
            'WSTG-ATHZ': 'Authorization Testing',
            'WSTG-SESS': 'Session Management Testing',
            'WSTG-INPV': 'Input Validation Testing',
            'WSTG-ERRH': 'Error Handling',
            'WSTG-CRYP': 'Cryptography',
            'WSTG-BUSLOGIC': 'Business Logic Testing',
            'WSTG-CLNT': 'Client-side Testing'
        }
        
        # Initialize test results storage
        self.test_results = {}
    
    def create_test_result(self, test_id: str, test_name: str) -> WSTGTestResult:
        """Create a new test result object"""
        result = WSTGTestResult(test_id, test_name)
        self.test_results[test_id] = result
        return result
    
    async def run_test_category(self, base_url: str, category: str, 
                               options: Dict[str, Any] = None) -> List[WSTGTestResult]:
        """Run all tests in a specific WSTG category"""
        if options is None:
            options = {}
        
        category_tests = {
            'WSTG-INFO': self._run_information_gathering_tests,
            'WSTG-CONF': self._run_configuration_tests,
            'WSTG-IDNT': self._run_identity_management_tests,
            'WSTG-ATHN': self._run_authentication_tests,
            'WSTG-ATHZ': self._run_authorization_tests,
            'WSTG-SESS': self._run_session_management_tests,
            'WSTG-INPV': self._run_input_validation_tests,
            'WSTG-ERRH': self._run_error_handling_tests,
            'WSTG-CRYP': self._run_cryptography_tests,
            'WSTG-BUSLOGIC': self._run_business_logic_tests,
            'WSTG-CLNT': self._run_client_side_tests
        }
        
        test_function = category_tests.get(category)
        if not test_function:
            self.logger.error(f"Unknown test category: {category}")
            return []
        
        self.logger.info(f"Running WSTG category {category} tests for {base_url}")
        self.security_logger.log_scan_start(base_url, 'WSTG', category)
        
        start_time = datetime.now()
        results = await test_function(base_url, options)
        end_time = datetime.now()
        
        duration = (end_time - start_time).total_seconds()
        findings_count = sum(len(result.findings) for result in results)
        
        self.security_logger.log_scan_complete(base_url, f'WSTG-{category}', duration, findings_count)
        
        return results
    
    async def _run_information_gathering_tests(self, base_url: str, 
                                             options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-INFO: Information Gathering Tests"""
        tests = [
            self._test_robots_txt,
            self._test_sitemap_xml,
            self._test_server_headers,
            self._test_technology_detection,
            self._test_directory_listing,
            self._test_backup_files,
            self._test_admin_interfaces,
            self._test_ssl_tls_config
        ]
        
        results = []
        for test_func in tests:
            try:
                result = await test_func(base_url, options)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error running {test_func.__name__}: {e}")
        
        return results
    
    async def _test_robots_txt(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """WSTG-INFO-01: Conduct search engine discovery reconnaissance for information leakage"""
        result = self.create_test_result('WSTG-INFO-01', 'Robots.txt Analysis')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url)
            
            if response.status_code == 200:
                result.add_finding(
                    "robots.txt file found",
                    {
                        'url': robots_url,
                        'content': response.text,
                        'size': len(response.text)
                    },
                    'info'
                )
                
                # Analyze robots.txt content for sensitive paths
                disallow_paths = []
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            disallow_paths.append(path)
                
                if disallow_paths:
                    result.add_finding(
                        f"Found {len(disallow_paths)} disallowed paths that may contain sensitive information",
                        {
                            'disallowed_paths': disallow_paths,
                            'potential_sensitive': [p for p in disallow_paths 
                                                  if any(keyword in p.lower() for keyword in 
                                                        ['admin', 'config', 'backup', 'private', 'secret', 'test'])]
                        },
                        'low'
                    )
                
                result.status = 'passed'
            else:
                result.add_finding(
                    "robots.txt file not found or not accessible",
                    {'status_code': response.status_code},
                    'info'
                )
                result.status = 'passed'
                
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_sitemap_xml(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """Test for sitemap.xml file"""
        result = self.create_test_result('WSTG-INFO-01b', 'Sitemap.xml Analysis')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemaps.xml']
            
            for sitemap_path in sitemap_urls:
                sitemap_url = urljoin(base_url, sitemap_path)
                response = self.session.get(sitemap_url)
                
                if response.status_code == 200:
                    result.add_finding(
                        f"Sitemap file found: {sitemap_path}",
                        {
                            'url': sitemap_url,
                            'content_type': response.headers.get('content-type', ''),
                            'size': len(response.text)
                        },
                        'info'
                    )
                    
                    # Parse XML to extract URLs
                    try:
                        from xml.etree import ElementTree as ET
                        root = ET.fromstring(response.text)
                        urls = []
                        for url_elem in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                            loc = url_elem.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                            if loc is not None:
                                urls.append(loc.text)
                        
                        if urls:
                            result.add_finding(
                                f"Extracted {len(urls)} URLs from sitemap",
                                {
                                    'urls': urls[:50],  # Limit to first 50
                                    'total_urls': len(urls)
                                },
                                'info'
                            )
                    except ET.ParseError:
                        pass
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_server_headers(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """WSTG-INFO-02: Fingerprint web server"""
        result = self.create_test_result('WSTG-INFO-02', 'Server Headers Analysis')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            response = self.session.get(base_url)
            headers = dict(response.headers)
            
            # Check for server information disclosure
            server_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
            disclosed_info = {}
            
            for header in server_headers:
                if header in headers:
                    disclosed_info[header] = headers[header]
            
            if disclosed_info:
                result.add_finding(
                    "Server information disclosed in HTTP headers",
                    {
                        'disclosed_headers': disclosed_info,
                        'recommendation': 'Remove or obfuscate server identification headers'
                    },
                    'low'
                )
            
            # Check for security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
                'X-XSS-Protection': 'Missing X-XSS-Protection header',
                'Strict-Transport-Security': 'Missing HSTS header',
                'Content-Security-Policy': 'Missing CSP header',
                'Referrer-Policy': 'Missing Referrer-Policy header'
            }
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in headers:
                    missing_headers.append(header)
            
            if missing_headers:
                result.add_finding(
                    f"Missing {len(missing_headers)} security headers",
                    {
                        'missing_headers': missing_headers,
                        'recommendation': 'Implement security headers to protect against common attacks'
                    },
                    'medium'
                )
            
            result.evidence['all_headers'] = headers
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_technology_detection(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """Detect web technologies in use"""
        result = self.create_test_result('WSTG-INFO-03', 'Technology Detection')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            response = self.session.get(base_url)
            
            technologies = {}
            
            # Analyze headers for technology indicators
            headers = response.headers
            if 'Server' in headers:
                technologies['web_server'] = headers['Server']
            
            if 'X-Powered-By' in headers:
                technologies['framework'] = headers['X-Powered-By']
            
            # Analyze HTML content
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Check for generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                technologies['cms'] = generator.get('content')
            
            # Check for common framework patterns
            if 'wp-content' in response.text or 'wp-includes' in response.text:
                technologies['cms'] = 'WordPress'
            
            if 'joomla' in response.text.lower():
                technologies['cms'] = 'Joomla'
            
            if 'drupal' in response.text.lower():
                technologies['cms'] = 'Drupal'
            
            # Check for JavaScript frameworks
            js_patterns = {
                'jQuery': r'jquery[.-](\d+\.\d+(?:\.\d+)?)',
                'Angular': r'angular[.-](\d+\.\d+(?:\.\d+)?)',
                'React': r'react[.-](\d+\.\d+(?:\.\d+)?)',
                'Vue.js': r'vue[.-](\d+\.\d+(?:\.\d+)?)'
            }
            
            for framework, pattern in js_patterns.items():
                match = re.search(pattern, response.text, re.IGNORECASE)
                if match:
                    technologies[f'js_{framework.lower()}'] = match.group(1) if match.groups() else 'detected'
            
            if technologies:
                result.add_finding(
                    f"Detected {len(technologies)} technologies",
                    {
                        'technologies': technologies,
                        'recommendation': 'Keep all detected technologies updated to latest versions'
                    },
                    'info'
                )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _run_configuration_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-CONF: Configuration and Deployment Management Testing"""
        tests = [
            self._test_ssl_tls_config,
            self._test_directory_listing,
            self._test_backup_files,
            self._test_admin_interfaces
        ]
        
        results = []
        for test_func in tests:
            try:
                result = await test_func(base_url, options)
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error running {test_func.__name__}: {e}")
        
        return results
    
    async def _test_directory_listing(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """WSTG-CONF-04: Review old backup and unreferenced files for sensitive information"""
        result = self.create_test_result('WSTG-CONF-04', 'Directory Listing Test')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            # Common directories to check
            directories = [
                '/admin/', '/backup/', '/config/', '/data/', '/db/', '/files/',
                '/images/', '/includes/', '/logs/', '/temp/', '/tmp/', '/uploads/'
            ]
            
            accessible_dirs = []
            
            for directory in directories:
                dir_url = urljoin(base_url, directory)
                response = self.session.get(dir_url)
                
                if response.status_code == 200 and 'Index of' in response.text:
                    accessible_dirs.append({
                        'directory': directory,
                        'url': dir_url,
                        'status_code': response.status_code
                    })
            
            if accessible_dirs:
                result.add_finding(
                    f"Directory listing enabled for {len(accessible_dirs)} directories",
                    {
                        'directories': accessible_dirs,
                        'recommendation': 'Disable directory listing and restrict access to sensitive directories'
                    },
                    'medium'
                )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_backup_files(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """Test for backup and temporary files"""
        result = self.create_test_result('WSTG-CONF-04b', 'Backup Files Detection')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            # Common backup file extensions and patterns
            backup_patterns = [
                '.bak', '.backup', '.old', '.orig', '.copy', '.tmp',
                '~', '.save', '.swp', '.config.old', 'config.bak'
            ]
            
            # Get the main page to derive potential backup filenames
            parsed_url = urlparse(base_url)
            base_path = parsed_url.path
            
            if base_path.endswith('/'):
                base_files = ['index.html', 'index.php', 'default.html', 'home.php']
            else:
                filename = base_path.split('/')[-1]
                base_files = [filename]
            
            found_backups = []
            
            for base_file in base_files:
                for pattern in backup_patterns:
                    backup_file = f"{base_file}{pattern}"
                    backup_url = urljoin(base_url, backup_file)
                    
                    response = self.session.head(backup_url)
                    if response.status_code == 200:
                        found_backups.append({
                            'file': backup_file,
                            'url': backup_url,
                            'size': response.headers.get('content-length', 'unknown')
                        })
            
            if found_backups:
                result.add_finding(
                    f"Found {len(found_backups)} potential backup files",
                    {
                        'backup_files': found_backups,
                        'recommendation': 'Remove backup files from web-accessible directories'
                    },
                    'high'
                )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_admin_interfaces(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """Test for admin interfaces"""
        result = self.create_test_result('WSTG-CONF-05', 'Admin Interface Detection')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            # Common admin paths
            admin_paths = [
                '/admin/', '/admin/login', '/administrator/', '/wp-admin/',
                '/phpmyadmin/', '/adminer/', '/manager/', '/console/',
                '/control/', '/cpanel/', '/dashboard/', '/panel/'
            ]
            
            found_admin_interfaces = []
            
            for path in admin_paths:
                admin_url = urljoin(base_url, path)
                response = self.session.get(admin_url)
                
                if response.status_code == 200:
                    # Check if it's really an admin interface
                    admin_indicators = ['admin', 'login', 'password', 'username', 'dashboard']
                    content_lower = response.text.lower()
                    
                    if any(indicator in content_lower for indicator in admin_indicators):
                        found_admin_interfaces.append({
                            'path': path,
                            'url': admin_url,
                            'title': self._extract_title(response.text),
                            'status_code': response.status_code
                        })
            
            if found_admin_interfaces:
                result.add_finding(
                    f"Found {len(found_admin_interfaces)} admin interfaces",
                    {
                        'admin_interfaces': found_admin_interfaces,
                        'recommendation': 'Restrict access to admin interfaces and use strong authentication'
                    },
                    'medium'
                )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    async def _test_ssl_tls_config(self, base_url: str, options: Dict[str, Any]) -> WSTGTestResult:
        """WSTG-CRYP-01: Testing for weak SSL/TLS ciphers"""
        result = self.create_test_result('WSTG-CRYP-01', 'SSL/TLS Configuration')
        result.start_time = datetime.now()
        result.status = 'running'
        
        try:
            parsed_url = urlparse(base_url)
            if parsed_url.scheme != 'https':
                result.add_finding(
                    "Site not using HTTPS",
                    {
                        'scheme': parsed_url.scheme,
                        'recommendation': 'Implement HTTPS with valid SSL certificate'
                    },
                    'high'
                )
                result.status = 'passed'
                result.end_time = datetime.now()
                return result
            
            hostname = parsed_url.hostname
            port = parsed_url.port or 443
            
            # Test SSL connection
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Check SSL/TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        result.add_finding(
                            f"Weak SSL/TLS version: {version}",
                            {
                                'version': version,
                                'recommendation': 'Upgrade to TLS 1.2 or higher'
                            },
                            'high'
                        )
                    
                    # Check cipher suite
                    if cipher:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name for weak in ['RC4', 'DES', 'MD5', 'SHA1']):
                            result.add_finding(
                                f"Weak cipher suite: {cipher_name}",
                                {
                                    'cipher': cipher,
                                    'recommendation': 'Configure strong cipher suites'
                                },
                                'medium'
                            )
                    
                    # Check certificate
                    if cert:
                        # Check for self-signed or expired certificate
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            result.add_finding(
                                "SSL certificate expired",
                                {
                                    'not_after': cert['notAfter'],
                                    'recommendation': 'Renew SSL certificate'
                                },
                                'high'
                            )
            
            result.status = 'passed'
            
        except Exception as e:
            result.error = str(e)
            result.status = 'error'
            
        result.end_time = datetime.now()
        return result
    
    def _extract_title(self, html_content: str) -> str:
        """Extract title from HTML content"""
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
            title_tag = soup.find('title')
            return title_tag.text.strip() if title_tag else 'No title'
        except:
            return 'Unknown'
    
    # Placeholder methods for other test categories
    async def _run_identity_management_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-IDNT: Identity Management Testing"""
        # TODO: Implement identity management tests
        return []
    
    async def _run_authentication_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-ATHN: Authentication Testing"""
        # TODO: Implement authentication tests
        return []
    
    async def _run_authorization_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-ATHZ: Authorization Testing"""
        # TODO: Implement authorization tests
        return []
    
    async def _run_session_management_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-SESS: Session Management Testing"""
        # TODO: Implement session management tests
        return []
    
    async def _run_input_validation_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-INPV: Input Validation Testing"""
        # TODO: Implement input validation tests
        return []
    
    async def _run_error_handling_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-ERRH: Error Handling"""
        # TODO: Implement error handling tests
        return []
    
    async def _run_cryptography_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-CRYP: Cryptography"""
        # TODO: Implement additional cryptography tests
        return []
    
    async def _run_business_logic_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-BUSLOGIC: Business Logic Testing"""
        # TODO: Implement business logic tests
        return []
    
    async def _run_client_side_tests(self, base_url: str, options: Dict[str, Any]) -> List[WSTGTestResult]:
        """WSTG-CLNT: Client-side Testing"""
        # TODO: Implement client-side tests
        return []
    
    def get_test_results(self, test_id: str = None) -> Union[WSTGTestResult, Dict[str, WSTGTestResult]]:
        """Get test results"""
        if test_id:
            return self.test_results.get(test_id)
        return self.test_results
    
    def get_summary_statistics(self) -> Dict[str, Any]:
        """Get summary statistics of all tests"""
        stats = {
            'total_tests': len(self.test_results),
            'passed': 0,
            'failed': 0,
            'error': 0,
            'pending': 0,
            'severity_counts': {'info': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0},
            'total_findings': 0,
            'categories': {}
        }
        
        for result in self.test_results.values():
            # Count by status
            stats[result.status] = stats.get(result.status, 0) + 1
            
            # Count by severity
            stats['severity_counts'][result.severity] += 1
            
            # Count findings
            stats['total_findings'] += len(result.findings)
            
            # Count by category
            category = result.test_id.split('-')[1] if '-' in result.test_id else 'OTHER'
            stats['categories'][category] = stats['categories'].get(category, 0) + 1
        
        return stats