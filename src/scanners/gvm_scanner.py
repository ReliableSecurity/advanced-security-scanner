"""
GVM/OpenVAS Integration Module
"""

import logging
import socket
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import asyncio

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    from gvm.errors import GvmError
    GVM_AVAILABLE = True
except ImportError:
    GVM_AVAILABLE = False

from core.config_manager import ConfigManager
from core.logger import get_security_logger

class GVMScanner:
    """GVM/OpenVAS scanner integration"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.security_logger = get_security_logger(__name__)
        
        if not GVM_AVAILABLE:
            self.logger.error("GVM libraries not available. Install with: pip install python-gvm")
            self.available = False
            return
            
        self.available = True
        self.config = self.config_manager.get_tool_config('gvm')
        self.gmp = None
        self.connection = None
        
        # Scan configurations
        self.scan_configs = {
            'full_and_fast': 'daba56c8-73ec-11df-a475-002264764cea',
            'full_and_deep': '74db13d6-7489-11df-91b9-002264764cea',
            'full_and_very_deep': '708f25c4-7489-11df-8094-002264764cea',
            'system_discovery': '8715c877-47a0-438d-98a3-27c7a6ab2196',
            'web_application': 'f2f2b3b4-5687-4b4d-8c98-26ee5c6d5b6d'
        }
        
        # Alive tests
        self.alive_tests = {
            'icmp_ping': '21f5c3ee-b4b1-4c73-8b8e-9b5c8f2a5c4d',
            'tcp_ack_service': 'cb4e1e6f-7d5a-4b5d-8c77-3e6f5a2b4c1d',
            'tcp_syn_service': 'e5b3f4c2-7a3b-4d1c-9a2b-1d3c4e5f6a7b',
            'arp_ping': 'a4b2c5d3-6e8f-4a1b-9c2d-7e8f1a2b3c4d'
        }
    
    def connect(self) -> bool:
        """Connect to GVM daemon"""
        if not self.available:
            return False
            
        try:
            # Use Unix socket if available, otherwise TLS connection
            socket_path = self.config.get('socket_path', '/var/run/gvm/gvmd.sock')
            
            if Path(socket_path).exists():
                self.connection = UnixSocketConnection(path=socket_path)
                self.logger.info(f"Connecting to GVM via Unix socket: {socket_path}")
            else:
                # TLS connection
                host = self.config.get('host', '127.0.0.1')
                port = self.config.get('port', 9390)
                self.connection = TLSConnection(hostname=host, port=port)
                self.logger.info(f"Connecting to GVM via TLS: {host}:{port}")
            
            # Create GMP instance
            transform = EtreeTransform()
            self.gmp = Gmp(connection=self.connection, transform=transform)
            
            # Authenticate
            username = self.config.get('username', 'admin')
            password = self.config.get('password', 'admin')
            
            if username and password:
                self.gmp.authenticate(username, password)
                self.security_logger.log_authentication('GVM', True, username)
                self.logger.info("Successfully connected and authenticated to GVM")
                return True
            else:
                self.logger.error("GVM username and password not configured")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to connect to GVM: {e}")
            self.security_logger.log_authentication('GVM', False)
            return False
    
    def disconnect(self):
        """Disconnect from GVM daemon"""
        try:
            if self.gmp:
                self.gmp.disconnect()
            if self.connection:
                self.connection.disconnect()
            self.logger.info("Disconnected from GVM")
        except Exception as e:
            self.logger.error(f"Error disconnecting from GVM: {e}")
    
    def get_scan_configs(self) -> Dict[str, str]:
        """Get available scan configurations"""
        if not self.gmp:
            return {}
        
        try:
            configs = self.gmp.get_scan_configs()
            config_dict = {}
            
            for config in configs.xpath('config'):
                config_id = config.get('id')
                name = config.find('name').text
                config_dict[name] = config_id
                
            return config_dict
            
        except Exception as e:
            self.logger.error(f"Failed to get scan configs: {e}")
            return self.scan_configs  # Return defaults
    
    def create_target(self, name: str, hosts: List[str], 
                     alive_test: str = 'icmp_ping') -> Optional[str]:
        """Create a scan target"""
        if not self.gmp:
            return None
        
        try:
            # Get alive test UUID
            alive_test_id = self.alive_tests.get(alive_test, 
                                               self.alive_tests['icmp_ping'])
            
            # Create target
            response = self.gmp.create_target(
                name=name,
                hosts=hosts,
                alive_test=alive_test_id
            )
            
            target_id = response.get('id')
            self.logger.info(f"Created target '{name}' with ID: {target_id}")
            return target_id
            
        except Exception as e:
            self.logger.error(f"Failed to create target: {e}")
            return None
    
    def create_task(self, name: str, target_id: str, 
                   config_name: str = 'full_and_fast') -> Optional[str]:
        """Create a scan task"""
        if not self.gmp:
            return None
        
        try:
            # Get scan config ID
            configs = self.get_scan_configs()
            config_id = configs.get(config_name)
            
            if not config_id:
                # Use default if not found
                config_id = self.scan_configs.get(config_name, 
                                                self.scan_configs['full_and_fast'])
            
            # Create task
            response = self.gmp.create_task(
                name=name,
                config_id=config_id,
                target_id=target_id,
                scanner_id='08b69003-5fc2-4037-a479-93b440211c73'  # OpenVAS scanner
            )
            
            task_id = response.get('id')
            self.logger.info(f"Created task '{name}' with ID: {task_id}")
            return task_id
            
        except Exception as e:
            self.logger.error(f"Failed to create task: {e}")
            return None
    
    def start_scan(self, task_id: str) -> bool:
        """Start a scan task"""
        if not self.gmp:
            return False
        
        try:
            response = self.gmp.start_task(task_id)
            
            # Check if start was successful
            status_text = response.get('status_text', '')
            if 'OK' in status_text:
                self.logger.info(f"Started scan task: {task_id}")
                return True
            else:
                self.logger.error(f"Failed to start scan: {status_text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to start scan: {e}")
            return False
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get task status and progress"""
        if not self.gmp:
            return {}
        
        try:
            response = self.gmp.get_task(task_id)
            task = response.find('task')
            
            if task is None:
                return {}
            
            status = task.find('status').text
            progress = task.find('progress').text if task.find('progress') is not None else '0'
            
            # Get report info if available
            reports = task.find('reports')
            report_id = None
            if reports is not None:
                last_report = reports.find('report/report')
                if last_report is not None:
                    report_id = last_report.get('id')
            
            return {
                'status': status,
                'progress': int(progress) if progress.isdigit() else 0,
                'report_id': report_id
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get task status: {e}")
            return {}
    
    def get_scan_results(self, task_id: str) -> List[Dict[str, Any]]:
        """Get scan results for a completed task"""
        if not self.gmp:
            return []
        
        try:
            # Get task to find report ID
            task_status = self.get_task_status(task_id)
            report_id = task_status.get('report_id')
            
            if not report_id:
                self.logger.warning(f"No report available for task: {task_id}")
                return []
            
            # Get detailed report
            report = self.gmp.get_report(report_id, details=True)
            
            return self.parse_scan_results(report)
            
        except Exception as e:
            self.logger.error(f"Failed to get scan results: {e}")
            return []
    
    def parse_scan_results(self, report_xml) -> List[Dict[str, Any]]:
        """Parse GVM scan results XML"""
        results = []
        
        try:
            # Find all results in the report
            for result in report_xml.xpath('.//result'):
                try:
                    # Extract basic information
                    result_data = {
                        'id': result.get('id', ''),
                        'name': self.get_text_safe(result, 'name'),
                        'description': self.get_text_safe(result, 'description'),
                        'severity': float(self.get_text_safe(result, 'severity', '0')),
                        'threat': self.get_text_safe(result, 'threat'),
                        'host': self.get_text_safe(result, 'host'),
                        'port': self.get_text_safe(result, 'port'),
                        'protocol': self.get_text_safe(result, 'protocol', 'tcp'),
                        'oid': self.get_text_safe(result, 'nvt/oid'),
                        'family': self.get_text_safe(result, 'nvt/family'),
                        'cve': [],
                        'references': [],
                        'solution': self.get_text_safe(result, 'nvt/solution'),
                        'impact': self.get_text_safe(result, 'nvt/impact'),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    # Extract CVE references
                    for ref in result.xpath('.//nvt/refs/ref[@type=\"cve\"]'):
                        if ref.get('id'):
                            result_data['cve'].append(ref.get('id'))
                    
                    # Extract other references
                    for ref in result.xpath('.//nvt/refs/ref[@type!=\"cve\"]'):
                        if ref.get('id'):
                            result_data['references'].append({
                                'type': ref.get('type'),
                                'id': ref.get('id')
                            })
                    
                    # Categorize severity
                    severity = result_data['severity']
                    if severity >= 9.0:
                        result_data['severity_level'] = 'Critical'
                    elif severity >= 7.0:
                        result_data['severity_level'] = 'High'
                    elif severity >= 4.0:
                        result_data['severity_level'] = 'Medium'
                    elif severity > 0.0:
                        result_data['severity_level'] = 'Low'
                    else:
                        result_data['severity_level'] = 'Info'
                    
                    results.append(result_data)
                    
                    # Log vulnerability found
                    self.security_logger.log_vulnerability_found(
                        target=result_data['host'],
                        vuln_type=result_data['name'],
                        severity=result_data['severity_level'],
                        details=f"Port {result_data['port']}/{result_data['protocol']}"
                    )
                    
                except Exception as e:
                    self.logger.error(f"Error parsing individual result: {e}")
                    continue
            
            self.logger.info(f"Parsed {len(results)} scan results")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to parse scan results: {e}")
            return []
    
    def get_text_safe(self, element, xpath: str, default: str = '') -> str:
        """Safely extract text from XML element"""
        try:
            found = element.find(xpath)
            return found.text if found is not None and found.text else default
        except:
            return default
    
    async def scan_target_async(self, target_name: str, hosts: List[str], 
                               config_name: str = 'full_and_fast') -> Dict[str, Any]:
        """Perform complete scan asynchronously"""
        
        scan_result = {
            'target_name': target_name,
            'hosts': hosts,
            'config_name': config_name,
            'status': 'starting',
            'progress': 0,
            'results': [],
            'task_id': None,
            'target_id': None,
            'start_time': datetime.now(),
            'end_time': None,
            'error': None
        }
        
        try:
            # Connect to GVM
            if not self.connect():
                scan_result['status'] = 'failed'
                scan_result['error'] = 'Failed to connect to GVM'
                return scan_result
            
            # Create target
            target_id = self.create_target(target_name, hosts)
            if not target_id:
                scan_result['status'] = 'failed'
                scan_result['error'] = 'Failed to create target'
                return scan_result
                
            scan_result['target_id'] = target_id
            scan_result['status'] = 'target_created'
            
            # Create task
            task_id = self.create_task(f"Scan_{target_name}_{int(time.time())}", 
                                     target_id, config_name)
            if not task_id:
                scan_result['status'] = 'failed'
                scan_result['error'] = 'Failed to create task'
                return scan_result
                
            scan_result['task_id'] = task_id
            scan_result['status'] = 'task_created'
            
            # Start scan
            if not self.start_scan(task_id):
                scan_result['status'] = 'failed'
                scan_result['error'] = 'Failed to start scan'
                return scan_result
            
            scan_result['status'] = 'running'
            self.security_logger.log_scan_start(target_name, 'GVM', config_name)
            
            # Monitor scan progress
            while True:
                await asyncio.sleep(10)  # Check every 10 seconds
                
                task_status = self.get_task_status(task_id)
                if not task_status:
                    break
                
                status = task_status['status']
                progress = task_status['progress']
                
                scan_result['progress'] = progress
                
                if status == 'Done':
                    # Scan completed, get results
                    scan_result['status'] = 'completed'
                    scan_result['end_time'] = datetime.now()
                    scan_result['results'] = self.get_scan_results(task_id)
                    
                    duration = (scan_result['end_time'] - scan_result['start_time']).total_seconds()
                    self.security_logger.log_scan_complete(
                        target_name, 'GVM', duration, len(scan_result['results'])
                    )
                    break
                    
                elif status in ['Interrupted', 'Stopped']:
                    scan_result['status'] = 'stopped'
                    scan_result['end_time'] = datetime.now()
                    break
                    
        except Exception as e:
            scan_result['status'] = 'failed'
            scan_result['error'] = str(e)
            scan_result['end_time'] = datetime.now()
            self.logger.error(f"Scan failed: {e}")
            
        finally:
            self.disconnect()
            
        return scan_result
    
    def get_vulnerability_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate statistics from scan results"""
        stats = {
            'total': len(results),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'unique_hosts': set(),
            'unique_ports': set(),
            'cve_count': 0,
            'families': {}
        }
        
        for result in results:
            severity_level = result.get('severity_level', 'Info')
            stats[severity_level.lower()] = stats.get(severity_level.lower(), 0) + 1
            
            stats['unique_hosts'].add(result.get('host', ''))
            if result.get('port'):
                stats['unique_ports'].add(f"{result['host']}:{result['port']}")
            
            stats['cve_count'] += len(result.get('cve', []))
            
            family = result.get('family', 'Unknown')
            stats['families'][family] = stats['families'].get(family, 0) + 1
        
        # Convert sets to counts
        stats['unique_hosts'] = len(stats['unique_hosts'])
        stats['unique_ports'] = len(stats['unique_ports'])
        
        return stats