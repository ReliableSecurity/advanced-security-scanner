"""
Fixed Plugin System with proper error handling and fallbacks
"""

import os
import sys
import json
import importlib.util
import asyncio
import logging
from typing import Dict, List, Any, Optional, Callable
from pathlib import Path
from abc import ABC, abstractmethod
from datetime import datetime
import pickle

# Optional imports with fallbacks
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic calculations")

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("Warning: Pandas not available, using basic data structures")

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.metrics import accuracy_score, precision_score, recall_score
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    print("Warning: Scikit-learn not available, AI analysis disabled")

try:
    import joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    import tensorflow as tf
    TENSORFLOW_AVAILABLE = True
except ImportError:
    TENSORFLOW_AVAILABLE = False
    print("Warning: TensorFlow not available, deep learning disabled")

try:
    from transformers import pipeline, AutoTokenizer, AutoModel
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Warning: Transformers not available, NLP analysis disabled")

from core.config_manager import ConfigManager
from core.logger import get_security_logger

class PluginInterface(ABC):
    """Abstract base class for all security scanner plugins"""
    
    @abstractmethod
    def get_info(self) -> Dict[str, Any]:
        """Return plugin information"""
        pass
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute scan and return results"""
        pass
    
    @abstractmethod
    def validate_target(self, target: str) -> bool:
        """Validate if target is supported by this plugin"""
        pass
    
    @abstractmethod
    def get_scan_options(self) -> Dict[str, Any]:
        """Return available scan options and their descriptions"""
        pass

class BasicVulnerabilityAnalyzer:
    """Basic vulnerability analysis without ML dependencies"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform basic vulnerability analysis"""
        if not vulnerabilities:
            return {"analysis": "No vulnerabilities to analyze"}
        
        analysis_results = {
            "total_vulnerabilities": len(vulnerabilities),
            "basic_analysis": {},
            "risk_score": 0.0,
            "priority_vulnerabilities": [],
            "recommendations": []
        }
        
        try:
            # Basic severity analysis
            severity_counts = self._count_by_severity(vulnerabilities)
            analysis_results["basic_analysis"]["severity_distribution"] = severity_counts
            
            # Basic risk score calculation
            risk_score = self._calculate_basic_risk_score(severity_counts)
            analysis_results["risk_score"] = risk_score
            
            # Identify high priority vulnerabilities
            priority_vulns = self._identify_priority_vulnerabilities(vulnerabilities)
            analysis_results["priority_vulnerabilities"] = priority_vulns
            
            # Generate basic recommendations
            recommendations = self._generate_basic_recommendations(vulnerabilities, severity_counts)
            analysis_results["recommendations"] = recommendations
            
            self.logger.info(f"Basic analysis completed for {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error in vulnerability analysis: {e}")
            analysis_results["error"] = str(e)
        
        return analysis_results
    
    def _count_by_severity(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count vulnerabilities by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts['low'] += 1
        
        return counts
    
    def _calculate_basic_risk_score(self, severity_counts: Dict[str, int]) -> float:
        """Calculate basic risk score based on severity distribution"""
        weights = {"critical": 4.0, "high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.5}
        total_weight = 0.0
        total_count = 0
        
        for severity, count in severity_counts.items():
            if count > 0:
                weight = weights.get(severity, 1.0)
                total_weight += weight * count
                total_count += count
        
        if total_count == 0:
            return 0.0
        
        # Normalize to 0-10 scale
        avg_severity = total_weight / total_count
        return min(10.0, (avg_severity / 4.0) * 10.0)
    
    def _identify_priority_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify high-priority vulnerabilities"""
        priority_vulns = []
        
        for vuln in vulnerabilities:
            priority_score = 0.0
            
            # Severity scoring
            severity = vuln.get('severity', 'low').lower()
            if severity == 'critical':
                priority_score += 50
            elif severity == 'high':
                priority_score += 40
            elif severity == 'medium':
                priority_score += 20
            
            # CVE scoring
            if vuln.get('cve'):
                priority_score += 15
            
            # Service criticality
            service = vuln.get('service', '').lower()
            if any(critical in service for critical in ['http', 'ssh', 'ftp', 'mysql', 'postgres']):
                priority_score += 10
            
            if priority_score >= 50:  # High priority threshold
                priority_vulns.append({
                    'vulnerability': vuln,
                    'priority_score': priority_score,
                    'reasoning': f"High priority due to {severity} severity and {service} service"
                })
        
        # Sort by priority score and return top 10
        priority_vulns.sort(key=lambda x: x['priority_score'], reverse=True)
        return priority_vulns[:10]
    
    def _generate_basic_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                      severity_counts: Dict[str, int]) -> List[Dict[str, Any]]:
        """Generate basic remediation recommendations"""
        recommendations = []
        
        # Critical vulnerabilities recommendation
        if severity_counts['critical'] > 0:
            recommendations.append({
                'type': 'immediate',
                'priority': 'critical',
                'title': 'Address Critical Vulnerabilities',
                'description': f'Found {severity_counts["critical"]} critical vulnerabilities requiring immediate attention.',
                'actions': [
                    'Patch systems immediately',
                    'Implement emergency controls',
                    'Monitor for exploitation attempts'
                ]
            })
        
        # High vulnerabilities recommendation
        if severity_counts['high'] > 0:
            recommendations.append({
                'type': 'urgent',
                'priority': 'high',
                'title': 'Remediate High-Risk Issues',
                'description': f'Found {severity_counts["high"]} high-risk vulnerabilities.',
                'actions': [
                    'Schedule patching within 72 hours',
                    'Review access controls',
                    'Increase monitoring'
                ]
            })
        
        # General security recommendation
        total_vulns = len(vulnerabilities)
        if total_vulns > 50:
            recommendations.append({
                'type': 'strategic',
                'priority': 'medium',
                'title': 'Improve Security Posture',
                'description': f'Large number of vulnerabilities ({total_vulns}) indicates systemic issues.',
                'actions': [
                    'Implement vulnerability management program',
                    'Automate security scanning',
                    'Conduct security training',
                    'Review security policies'
                ]
            })
        
        return recommendations

class AIVulnerabilityAnalyzer:
    """Advanced AI-powered vulnerability analysis with fallbacks"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
        
        # Use basic analyzer if ML libraries not available
        if not (SKLEARN_AVAILABLE and NUMPY_AVAILABLE):
            self.basic_analyzer = BasicVulnerabilityAnalyzer(config_manager)
            self.use_basic = True
        else:
            self.use_basic = False
            self._initialize_models()
    
    def _initialize_models(self):
        """Initialize ML models if available"""
        try:
            if SKLEARN_AVAILABLE:
                # Initialize basic ML models
                self.severity_model = GradientBoostingClassifier(
                    n_estimators=100, learning_rate=0.1, max_depth=3, random_state=42
                )
                self.exploit_model = RandomForestClassifier(
                    n_estimators=200, max_depth=5, random_state=42
                )
                self.scaler = StandardScaler()
                
                self.logger.info("ML models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing ML models: {e}")
            self.use_basic = True
            self.basic_analyzer = BasicVulnerabilityAnalyzer(self.config_manager)
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform vulnerability analysis with AI if available"""
        if self.use_basic:
            return await self.basic_analyzer.analyze_vulnerabilities(vulnerabilities)
        
        # AI-powered analysis
        return await self._ai_analysis(vulnerabilities)
    
    async def _ai_analysis(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform AI-powered analysis"""
        if not vulnerabilities:
            return {"analysis": "No vulnerabilities to analyze"}
        
        analysis_results = {
            "total_vulnerabilities": len(vulnerabilities),
            "ai_analysis": {},
            "predictions": {},
            "recommendations": [],
            "risk_score": 0.0,
            "priority_vulnerabilities": []
        }
        
        try:
            # Extract features if possible
            if PANDAS_AVAILABLE and NUMPY_AVAILABLE:
                features_df = self._extract_features(vulnerabilities)
                
                # Perform predictions
                severity_predictions = await self._predict_severity(features_df)
                analysis_results["predictions"]["severity"] = severity_predictions
                
                # Calculate risk score
                risk_score = await self._calculate_ai_risk_score(features_df)
                analysis_results["risk_score"] = risk_score
                
            # Generate recommendations
            recommendations = await self._generate_ai_recommendations(vulnerabilities)
            analysis_results["recommendations"] = recommendations
            
            self.logger.info(f"AI analysis completed for {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error in AI analysis: {e}")
            # Fallback to basic analysis
            return await self.basic_analyzer.analyze_vulnerabilities(vulnerabilities)
        
        return analysis_results
    
    def _extract_features(self, vulnerabilities: List[Dict[str, Any]]):
        """Extract features for ML models"""
        if not PANDAS_AVAILABLE:
            return None
        
        features = []
        for vuln in vulnerabilities:
            feature_vector = {
                'severity_score': self._severity_to_score(vuln.get('severity', 'low')),
                'cvss_score': float(vuln.get('cvss_score', 0.0)),
                'has_cve': 1 if vuln.get('cve') else 0,
                'service_critical': 1 if any(svc in vuln.get('service', '').lower() 
                                           for svc in ['http', 'ssh', 'mysql']) else 0,
                'description_length': len(vuln.get('description', '')),
            }
            features.append(feature_vector)
        
        return pd.DataFrame(features)
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity to numerical score"""
        severity_map = {
            'critical': 4.0, 'high': 3.0, 'medium': 2.0, 'low': 1.0, 'info': 0.0
        }
        return severity_map.get(severity.lower(), 1.0)
    
    async def _predict_severity(self, features_df) -> List[Dict[str, Any]]:
        """Predict vulnerability severity"""
        predictions = []
        
        for idx, row in features_df.iterrows():
            # Simple rule-based prediction as fallback
            base_score = row['severity_score']
            cvss_influence = row['cvss_score'] / 10.0
            adjusted_score = min(4.0, base_score + cvss_influence * 0.5)
            
            severity_labels = ['info', 'low', 'medium', 'high', 'critical']
            predicted_severity = severity_labels[min(4, int(adjusted_score))]
            confidence = min(0.95, 0.7 + (adjusted_score / 4.0) * 0.25)
            
            predictions.append({
                'vulnerability_id': idx,
                'predicted_severity': predicted_severity,
                'confidence': confidence,
                'score': adjusted_score
            })
        
        return predictions
    
    async def _calculate_ai_risk_score(self, features_df) -> float:
        """Calculate AI-based risk score"""
        if features_df.empty:
            return 0.0
        
        # Basic calculation using available features
        avg_severity = features_df['severity_score'].mean()
        avg_cvss = features_df['cvss_score'].mean()
        critical_services = features_df['service_critical'].sum()
        
        # Combine factors
        risk_score = (avg_severity / 4.0) * 4 + (avg_cvss / 10.0) * 3 + min(1.0, critical_services / 5.0) * 3
        
        return min(10.0, risk_score)
    
    async def _generate_ai_recommendations(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate AI-powered recommendations"""
        # For now, use enhanced rule-based recommendations
        recommendations = []
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low').lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Critical vulnerabilities
        if severity_counts.get('critical', 0) > 0:
            recommendations.append({
                'type': 'immediate',
                'priority': 'critical',
                'title': 'Emergency Response Required',
                'description': f'Detected {severity_counts["critical"]} critical vulnerabilities',
                'actions': [
                    'Implement emergency patches',
                    'Isolate affected systems',
                    'Enable enhanced monitoring',
                    'Notify security team immediately'
                ],
                'ai_confidence': 0.95
            })
        
        # Pattern-based recommendations
        web_vulns = sum(1 for v in vulnerabilities if 'web' in v.get('type', '').lower())
        if web_vulns > len(vulnerabilities) * 0.5:
            recommendations.append({
                'type': 'strategic',
                'priority': 'high',
                'title': 'Web Application Security Focus',
                'description': 'High concentration of web application vulnerabilities detected',
                'actions': [
                    'Implement Web Application Firewall',
                    'Conduct code security review',
                    'Enable runtime protection',
                    'Train developers on secure coding'
                ],
                'ai_confidence': 0.85
            })
        
        return recommendations

class PluginManager:
    """Enhanced plugin management system"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
        
        self.plugins: Dict[str, PluginInterface] = {}
        self.plugin_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Plugin directories
        self.plugin_dirs = [
            Path(__file__).parent / "official_plugins",
            Path(__file__).parent / "community_plugins", 
            Path(__file__).parent / "custom_plugins"
        ]
        
        # Initialize analyzer
        self.ai_analyzer = AIVulnerabilityAnalyzer(config_manager)
        
        # Initialize plugins
        self._discover_and_load_plugins()
    
    def _discover_and_load_plugins(self):
        """Discover and load all available plugins"""
        self.logger.info("Discovering security scanner plugins...")
        
        # Create plugin directories if they don't exist
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                plugin_dir.mkdir(parents=True, exist_ok=True)
                # Create example plugin file
                self._create_example_plugin(plugin_dir)
                continue
            
            # Load plugins from directory
            for plugin_file in plugin_dir.glob("*.py"):
                if plugin_file.name.startswith("__") or plugin_file.name.startswith("example_"):
                    continue
                
                try:
                    self._load_plugin(plugin_file)
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {plugin_file}: {e}")
        
        self.logger.info(f"Loaded {len(self.plugins)} plugins")
    
    def _create_example_plugin(self, plugin_dir: Path):
        """Create example plugin file"""
        example_plugin = plugin_dir / "example_nmap_plugin.py"
        if not example_plugin.exists():
            example_code = '''"""
Example Nmap Plugin for Security Scanner
"""
import asyncio
import subprocess
import json
from typing import Dict, List, Any
from plugins.plugin_manager_fixed import PluginInterface

class NmapPlugin(PluginInterface):
    """Example Nmap integration plugin"""
    
    def get_info(self) -> Dict[str, Any]:
        return {
            'name': 'nmap',
            'version': '1.0.0',
            'description': 'Network port scanner',
            'author': 'Security Scanner Team',
            'category': 'network'
        }
    
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute nmap scan"""
        try:
            cmd = ['nmap', '-sV', '-T4', target]
            if options.get('aggressive', False):
                cmd.extend(['-A', '-O'])
            
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            return {
                'tool': 'nmap',
                'target': target,
                'status': 'completed' if process.returncode == 0 else 'failed',
                'results': stdout.decode(),
                'errors': stderr.decode() if stderr else None,
                'vulnerabilities': self._parse_nmap_output(stdout.decode())
            }
            
        except Exception as e:
            return {
                'tool': 'nmap',
                'target': target,
                'status': 'error',
                'error': str(e),
                'vulnerabilities': []
            }
    
    def validate_target(self, target: str) -> bool:
        """Validate target format"""
        import re
        # Simple IP/hostname validation
        ip_pattern = r'^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$'
        hostname_pattern = r'^[a-zA-Z0-9.-]+$'
        return bool(re.match(ip_pattern, target) or re.match(hostname_pattern, target))
    
    def get_scan_options(self) -> Dict[str, Any]:
        """Get available scan options"""
        return {
            'aggressive': {'type': 'boolean', 'default': False, 'description': 'Enable aggressive scanning'},
            'port_range': {'type': 'string', 'default': '', 'description': 'Custom port range'},
            'scan_type': {'type': 'select', 'options': ['tcp', 'udp', 'syn'], 'default': 'tcp'}
        }
    
    def _parse_nmap_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse nmap output for vulnerabilities"""
        vulnerabilities = []
        
        # Simple parsing - in real implementation, parse nmap XML output
        lines = output.split('\\n')
        for line in lines:
            if 'open' in line and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 2:
                    port = parts[0].split('/')[0]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    
                    vulnerabilities.append({
                        'type': 'Open Port',
                        'severity': 'info',
                        'port': port,
                        'service': service,
                        'description': f'Open {service} service on port {port}',
                        'tool': 'nmap'
                    })
        
        return vulnerabilities
'''
            
            example_plugin.write_text(example_code)
    
    def _load_plugin(self, plugin_file: Path):
        """Load a single plugin from file"""
        module_name = plugin_file.stem
        
        try:
            # Load module
            spec = importlib.util.spec_from_file_location(module_name, plugin_file)
            if not spec or not spec.loader:
                raise ValueError(f"Cannot load module spec from {plugin_file}")
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin class
            plugin_class = None
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and 
                    issubclass(attr, PluginInterface) and 
                    attr != PluginInterface):
                    plugin_class = attr
                    break
            
            if not plugin_class:
                raise ValueError(f"No valid plugin class found in {plugin_file}")
            
            # Instantiate plugin
            plugin = plugin_class()
            plugin_info = plugin.get_info()
            
            plugin_name = plugin_info.get('name', module_name)
            
            self.plugins[plugin_name] = plugin
            self.plugin_metadata[plugin_name] = plugin_info
            
            self.logger.info(f"Loaded plugin: {plugin_name} v{plugin_info.get('version', 'unknown')}")
            
        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_file}: {e}")
    
    def get_available_plugins(self) -> Dict[str, Dict[str, Any]]:
        """Get list of available plugins"""
        return self.plugin_metadata.copy()
    
    def get_plugin(self, name: str) -> Optional[PluginInterface]:
        """Get plugin by name"""
        return self.plugins.get(name)
    
    async def execute_plugin(self, plugin_name: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute a specific plugin"""
        if plugin_name not in self.plugins:
            raise ValueError(f"Plugin '{plugin_name}' not found")
        
        plugin = self.plugins[plugin_name]
        
        # Validate target
        if not plugin.validate_target(target):
            raise ValueError(f"Target '{target}' is not valid for plugin '{plugin_name}'")
        
        options = options or {}
        
        self.logger.info(f"Executing plugin '{plugin_name}' on target '{target}'")
        
        try:
            results = await plugin.scan(target, options)
            
            # Add metadata
            results['plugin_info'] = self.plugin_metadata[plugin_name]
            results['execution_time'] = datetime.now().isoformat()
            
            return results
            
        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            return {
                'error': str(e),
                'plugin_info': self.plugin_metadata[plugin_name],
                'execution_time': datetime.now().isoformat()
            }
    
    async def execute_multiple_plugins(self, plugin_names: List[str], target: str, 
                                     options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute multiple plugins concurrently"""
        if not plugin_names:
            return {'results': {}, 'summary': 'No plugins specified'}
        
        self.logger.info(f"Executing {len(plugin_names)} plugins on target '{target}'")
        
        # Create tasks for concurrent execution
        tasks = []
        for plugin_name in plugin_names:
            if plugin_name in self.plugins:
                task = self.execute_plugin(plugin_name, target, options)
                tasks.append((plugin_name, task))
        
        # Execute all plugins concurrently
        results = {}
        if tasks:
            completed_tasks = await asyncio.gather(
                *[task for _, task in tasks], 
                return_exceptions=True
            )
            
            # Process results
            for (plugin_name, _), result in zip(tasks, completed_tasks):
                if isinstance(result, Exception):
                    results[plugin_name] = {
                        'error': str(result),
                        'plugin_info': self.plugin_metadata.get(plugin_name, {})
                    }
                else:
                    results[plugin_name] = result
        
        # Aggregate vulnerabilities for analysis
        all_vulnerabilities = []
        for plugin_result in results.values():
            if 'vulnerabilities' in plugin_result and isinstance(plugin_result['vulnerabilities'], list):
                all_vulnerabilities.extend(plugin_result['vulnerabilities'])
        
        # Perform analysis
        ai_analysis = await self.ai_analyzer.analyze_vulnerabilities(all_vulnerabilities)
        
        return {
            'results': results,
            'ai_analysis': ai_analysis,
            'summary': {
                'plugins_executed': len(results),
                'total_vulnerabilities': len(all_vulnerabilities),
                'execution_time': datetime.now().isoformat(),
                'target': target
            }
        }
    
    def install_plugin(self, plugin_path: str, plugin_type: str = "custom") -> bool:
        """Install a new plugin"""
        try:
            source_path = Path(plugin_path)
            if not source_path.exists():
                raise FileNotFoundError(f"Plugin file not found: {plugin_path}")
            
            # Determine destination directory
            dest_dir = self.plugin_dirs[-1]  # Use custom_plugins as default
            for plugin_dir in self.plugin_dirs:
                if plugin_type in str(plugin_dir):
                    dest_dir = plugin_dir
                    break
            
            # Copy plugin file
            dest_path = dest_dir / source_path.name
            dest_path.write_text(source_path.read_text())
            
            # Load the new plugin
            self._load_plugin(dest_path)
            
            self.logger.info(f"Plugin installed successfully: {dest_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to install plugin: {e}")
            return False
    
    def get_plugin_options(self, plugin_name: str) -> Dict[str, Any]:
        """Get available options for a plugin"""
        if plugin_name not in self.plugins:
            return {}
        
        return self.plugins[plugin_name].get_scan_options()