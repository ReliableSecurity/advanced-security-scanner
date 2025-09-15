"""
Nuclei Integration Module
"""

import json
import subprocess
import asyncio
import logging
import tempfile
import os
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path

from core.config_manager import ConfigManager
from core.logger import get_security_logger

class NucleiScanner:
    """Nuclei vulnerability scanner integration"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = logging.getLogger(__name__)
        self.security_logger = get_security_logger(__name__)
        
        self.config = self.config_manager.get_tool_config('nuclei')
        self.binary_path = self.config.get('binary_path', '/usr/bin/nuclei')
        self.templates_dir = self.config.get('templates_dir', '/home/nuclei-templates')
        
        self.available = self._check_availability()
        
        # Template categories
        self.template_categories = {
            'cves': 'Known CVE vulnerabilities',
            'exposed-panels': 'Exposed admin panels and dashboards',
            'technologies': 'Technology detection',
            'vulnerabilities': 'General vulnerabilities',
            'misconfiguration': 'Configuration issues', 
            'takeovers': 'Subdomain takeovers',
            'default-logins': 'Default credentials',
            'dns': 'DNS-related issues',
            'fuzzing': 'Fuzzing templates',
            'headless': 'Headless browser tests',
            'iot': 'IoT device vulnerabilities',
            'network': 'Network service tests',
            'ssl': 'SSL/TLS vulnerabilities'
        }
    
    def _check_availability(self) -> bool:
        """Check if nuclei is available and working"""
        try:
            result = subprocess.run(
                [self.binary_path, '-version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                self.logger.info(f"Nuclei available: {result.stdout.strip()}")
                return True
            else:
                self.logger.error(f"Nuclei not working: {result.stderr}")
                return False
                
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            self.logger.error(f"Nuclei not available: {e}")
            return False
    
    def update_templates(self) -> bool:
        """Update nuclei templates"""
        if not self.available:
            return False
        
        try:
            self.logger.info("Updating nuclei templates...")
            
            cmd = [self.binary_path, '-update-templates']
            if self.templates_dir:
                cmd.extend(['-update-directory', str(self.templates_dir)])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode == 0:
                self.logger.info("Templates updated successfully")
                self.security_logger.log_tool_execution('nuclei', ' '.join(cmd), 0)
                return True
            else:
                self.logger.error(f"Failed to update templates: {result.stderr}")
                self.security_logger.log_tool_execution('nuclei', ' '.join(cmd), result.returncode)
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.error("Template update timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error updating templates: {e}")
            return False
    
    def get_template_stats(self) -> Dict[str, int]:
        """Get statistics about available templates"""
        stats = {}
        
        if not self.available:
            return stats
        
        try:
            # Get template list
            result = subprocess.run(
                [self.binary_path, '-tl'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                for category in self.template_categories:
                    count = sum(1 for line in lines if f"/{category}/" in line)
                    stats[category] = count
                    
                stats['total'] = len(lines)
                
        except Exception as e:
            self.logger.error(f"Error getting template stats: {e}")
        
        return stats
    
    def build_command(self, targets: List[str], options: Dict[str, Any]) -> List[str]:
        """Build nuclei command with options"""
        cmd = [self.binary_path]
        
        # Output format
        cmd.extend(['-json', '-silent'])
        
        # Rate limiting
        rate_limit = options.get('rate_limit', self.config.get('rate_limit', 150))
        cmd.extend(['-rate-limit', str(rate_limit)])
        
        # Bulk size
        bulk_size = options.get('bulk_size', self.config.get('bulk_size', 25))
        cmd.extend(['-bulk-size', str(bulk_size)])
        
        # Timeout
        timeout = options.get('timeout', self.config.get('timeout', 10))
        cmd.extend(['-timeout', str(timeout)])
        
        # Threads
        threads = options.get('threads', 25)
        cmd.extend(['-c', str(threads)])
        
        # Templates
        templates = options.get('templates', [])\n        if templates:\n            if isinstance(templates, list):\n                for template in templates:\n                    if template in self.template_categories:\n                        # Category-based template selection\n                        template_path = Path(self.templates_dir) / template\n                        if template_path.exists():\n                            cmd.extend(['-t', str(template_path)])\n                    else:\n                        # Direct template path\n                        cmd.extend(['-t', template])\n            else:\n                cmd.extend(['-t', templates])\n        \n        # Severity filtering\n        severity = options.get('severity', [])\n        if severity:\n            if isinstance(severity, list):\n                cmd.extend(['-severity', ','.join(severity)])\n            else:\n                cmd.extend(['-severity', severity])\n        \n        # Tags\n        tags = options.get('tags', [])\n        if tags:\n            if isinstance(tags, list):\n                cmd.extend(['-tags', ','.join(tags)])\n            else:\n                cmd.extend(['-tags', tags])\n        \n        # Exclude tags\n        exclude_tags = options.get('exclude_tags', [])\n        if exclude_tags:\n            if isinstance(exclude_tags, list):\n                cmd.extend(['-exclude-tags', ','.join(exclude_tags)])\n            else:\n                cmd.extend(['-exclude-tags', exclude_tags])\n        \n        # Custom headers\n        headers = options.get('headers', {})\n        for header, value in headers.items():\n            cmd.extend(['-H', f\"{header}: {value}\"])\n        \n        # Follow redirects\n        if options.get('follow_redirects', True):\n            cmd.append('-fr')\n        \n        # Include response in output\n        if options.get('include_response', False):\n            cmd.append('-include-rr')\n        \n        # Proxy settings\n        proxy = options.get('proxy')\n        if proxy:\n            cmd.extend(['-proxy', proxy])\n        \n        # Resume file\n        resume_file = options.get('resume_file')\n        if resume_file:\n            cmd.extend(['-resume', resume_file])\n        \n        # Add targets\n        if len(targets) == 1:\n            cmd.extend(['-target', targets[0]])\n        else:\n            # Create temporary file for multiple targets\n            temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')\n            temp_file.write('\\n'.join(targets))\n            temp_file.close()\n            cmd.extend(['-list', temp_file.name])\n        \n        return cmd\n    \n    async def scan_async(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:\n        \"\"\"Perform nuclei scan asynchronously\"\"\"\n        if not self.available:\n            return {\n                'status': 'failed',\n                'error': 'Nuclei not available',\n                'results': []\n            }\n        \n        if options is None:\n            options = {}\n        \n        scan_result = {\n            'targets': targets,\n            'status': 'running',\n            'results': [],\n            'start_time': datetime.now(),\n            'end_time': None,\n            'command': None,\n            'stats': {},\n            'error': None\n        }\n        \n        try:\n            # Build command\n            cmd = self.build_command(targets, options)\n            scan_result['command'] = ' '.join(cmd)\n            \n            self.logger.info(f\"Starting nuclei scan: {scan_result['command']}\")\n            self.security_logger.log_scan_start(','.join(targets[:3]), 'nuclei', 'custom')\n            \n            # Execute scan\n            process = await asyncio.create_subprocess_exec(\n                *cmd,\n                stdout=asyncio.subprocess.PIPE,\n                stderr=asyncio.subprocess.PIPE\n            )\n            \n            stdout, stderr = await process.communicate()\n            \n            scan_result['end_time'] = datetime.now()\n            duration = (scan_result['end_time'] - scan_result['start_time']).total_seconds()\n            \n            if process.returncode == 0 or stdout:\n                # Parse results even if returncode != 0, as nuclei may return findings\n                scan_result['results'] = self.parse_results(stdout.decode('utf-8'))\n                scan_result['status'] = 'completed'\n                scan_result['stats'] = self.generate_stats(scan_result['results'])\n                \n                self.security_logger.log_scan_complete(\n                    ','.join(targets[:3]), 'nuclei', duration, len(scan_result['results'])\n                )\n                \n            else:\n                scan_result['status'] = 'failed'\n                scan_result['error'] = stderr.decode('utf-8')\n                self.logger.error(f\"Nuclei scan failed: {scan_result['error']}\")\n            \n            self.security_logger.log_tool_execution('nuclei', scan_result['command'], process.returncode)\n            \n        except Exception as e:\n            scan_result['status'] = 'failed'\n            scan_result['error'] = str(e)\n            scan_result['end_time'] = datetime.now()\n            self.logger.error(f\"Nuclei scan exception: {e}\")\n        \n        finally:\n            # Clean up temporary files\n            self.cleanup_temp_files()\n        \n        return scan_result\n    \n    def parse_results(self, output: str) -> List[Dict[str, Any]]:\n        \"\"\"Parse nuclei JSON output\"\"\"\n        results = []\n        \n        if not output.strip():\n            return results\n        \n        for line in output.strip().split('\\n'):\n            if not line.strip():\n                continue\n            \n            try:\n                result = json.loads(line)\n                \n                # Extract and normalize result data\n                parsed_result = {\n                    'template_id': result.get('template-id', ''),\n                    'name': result.get('info', {}).get('name', ''),\n                    'description': result.get('info', {}).get('description', ''),\n                    'severity': result.get('info', {}).get('severity', 'info'),\n                    'tags': result.get('info', {}).get('tags', []),\n                    'reference': result.get('info', {}).get('reference', []),\n                    'classification': result.get('info', {}).get('classification', {}),\n                    'host': result.get('host', ''),\n                    'matched_at': result.get('matched-at', ''),\n                    'extracted_results': result.get('extracted-results', []),\n                    'request': result.get('request', ''),\n                    'response': result.get('response', ''),\n                    'curl_command': result.get('curl-command', ''),\n                    'timestamp': datetime.now().isoformat(),\n                    'type': result.get('type', 'http')\n                }\n                \n                # Add CVE information if available\n                cve_ids = []\n                classification = parsed_result.get('classification', {})\n                if 'cve-id' in classification:\n                    cve_id = classification['cve-id']\n                    if isinstance(cve_id, list):\n                        cve_ids.extend(cve_id)\n                    else:\n                        cve_ids.append(cve_id)\n                \n                parsed_result['cve'] = cve_ids\n                \n                # Categorize severity level\n                severity = parsed_result['severity'].lower()\n                if severity == 'critical':\n                    parsed_result['severity_level'] = 'Critical'\n                elif severity == 'high':\n                    parsed_result['severity_level'] = 'High'\n                elif severity == 'medium':\n                    parsed_result['severity_level'] = 'Medium'\n                elif severity == 'low':\n                    parsed_result['severity_level'] = 'Low'\n                else:\n                    parsed_result['severity_level'] = 'Info'\n                \n                results.append(parsed_result)\n                \n                # Log vulnerability\n                self.security_logger.log_vulnerability_found(\n                    target=parsed_result['host'],\n                    vuln_type=parsed_result['name'],\n                    severity=parsed_result['severity_level'],\n                    details=parsed_result['template_id']\n                )\n                \n            except json.JSONDecodeError as e:\n                self.logger.error(f\"Failed to parse nuclei result line: {e}\")\n                continue\n            except Exception as e:\n                self.logger.error(f\"Error processing nuclei result: {e}\")\n                continue\n        \n        self.logger.info(f\"Parsed {len(results)} nuclei results\")\n        return results\n    \n    def generate_stats(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:\n        \"\"\"Generate statistics from scan results\"\"\"\n        stats = {\n            'total': len(results),\n            'critical': 0,\n            'high': 0,\n            'medium': 0,\n            'low': 0,\n            'info': 0,\n            'unique_hosts': set(),\n            'unique_templates': set(),\n            'tags': {},\n            'severity_distribution': {},\n            'template_categories': {},\n            'cve_count': 0\n        }\n        \n        for result in results:\n            severity_level = result.get('severity_level', 'Info')\n            stats[severity_level.lower()] += 1\n            \n            stats['unique_hosts'].add(result.get('host', ''))\n            stats['unique_templates'].add(result.get('template_id', ''))\n            \n            # Count tags\n            for tag in result.get('tags', []):\n                stats['tags'][tag] = stats['tags'].get(tag, 0) + 1\n            \n            # Count CVEs\n            stats['cve_count'] += len(result.get('cve', []))\n            \n            # Template categories\n            template_id = result.get('template_id', '')\n            for category in self.template_categories:\n                if category in template_id:\n                    stats['template_categories'][category] = stats['template_categories'].get(category, 0) + 1\n                    break\n        \n        # Convert sets to counts\n        stats['unique_hosts'] = len(stats['unique_hosts'])\n        stats['unique_templates'] = len(stats['unique_templates'])\n        \n        # Calculate severity distribution percentages\n        if stats['total'] > 0:\n            for severity in ['critical', 'high', 'medium', 'low', 'info']:\n                percentage = (stats[severity] / stats['total']) * 100\n                stats['severity_distribution'][severity] = round(percentage, 1)\n        \n        return stats\n    \n    def cleanup_temp_files(self):\n        \"\"\"Clean up temporary files created during scanning\"\"\"\n        try:\n            # Clean up any temporary target files\n            temp_dir = Path(tempfile.gettempdir())\n            for temp_file in temp_dir.glob(\"tmp*.txt\"):\n                if temp_file.stat().st_mtime < (datetime.now().timestamp() - 3600):  # Older than 1 hour\n                    temp_file.unlink()\n        except Exception as e:\n            self.logger.error(f\"Error cleaning temp files: {e}\")\n    \n    def get_template_info(self, template_id: str) -> Dict[str, Any]:\n        \"\"\"Get detailed information about a specific template\"\"\"\n        if not self.available:\n            return {}\n        \n        try:\n            cmd = [self.binary_path, '-t', template_id, '-json', '-duc']\n            result = subprocess.run(\n                cmd,\n                capture_output=True,\n                text=True,\n                timeout=30\n            )\n            \n            if result.returncode == 0 and result.stdout:\n                return json.loads(result.stdout.strip())\n                \n        except Exception as e:\n            self.logger.error(f\"Error getting template info: {e}\")\n        \n        return {}\n    \n    def validate_templates(self, template_paths: List[str]) -> Dict[str, bool]:\n        \"\"\"Validate template files\"\"\"\n        validation_results = {}\n        \n        if not self.available:\n            return validation_results\n        \n        for template_path in template_paths:\n            try:\n                cmd = [self.binary_path, '-t', template_path, '-validate']\n                result = subprocess.run(\n                    cmd,\n                    capture_output=True,\n                    text=True,\n                    timeout=30\n                )\n                \n                validation_results[template_path] = result.returncode == 0\n                \n            except Exception as e:\n                self.logger.error(f\"Error validating template {template_path}: {e}\")\n                validation_results[template_path] = False\n        \n        return validation_results\n    \n    def get_preset_scan_options(self, preset: str) -> Dict[str, Any]:\n        \"\"\"Get predefined scan option presets\"\"\"\n        presets = {\n            'quick': {\n                'templates': ['cves', 'exposed-panels'],\n                'severity': ['critical', 'high'],\n                'rate_limit': 200,\n                'timeout': 5,\n                'threads': 50\n            },\n            'comprehensive': {\n                'templates': ['cves', 'exposed-panels', 'vulnerabilities', 'misconfiguration'],\n                'severity': ['critical', 'high', 'medium'],\n                'rate_limit': 100,\n                'timeout': 10,\n                'threads': 25\n            },\n            'deep': {\n                'templates': list(self.template_categories.keys()),\n                'severity': ['critical', 'high', 'medium', 'low'],\n                'rate_limit': 50,\n                'timeout': 15,\n                'threads': 10\n            },\n            'cve_only': {\n                'templates': ['cves'],\n                'severity': ['critical', 'high', 'medium'],\n                'rate_limit': 150,\n                'timeout': 10,\n                'threads': 30\n            },\n            'web_apps': {\n                'templates': ['exposed-panels', 'vulnerabilities', 'default-logins'],\n                'tags': ['panel', 'login', 'auth'],\n                'severity': ['critical', 'high', 'medium'],\n                'rate_limit': 100,\n                'timeout': 10\n            }\n        }\n        \n        return presets.get(preset, {})