"""
Advanced Plugin System and AI-Powered Analysis Engine
Extensible architecture for integrating new security tools and AI analysis
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
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score
import joblib
import tensorflow as tf
from transformers import pipeline, AutoTokenizer, AutoModel
import torch

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

class AIVulnerabilityAnalyzer:
    """Advanced AI-powered vulnerability analysis engine"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
        
        # ML models for different analysis tasks
        self.models = {}
        self.scalers = {}
        
        # NLP models for vulnerability description analysis
        self.nlp_models = {}
        
        # Initialize models
        self._initialize_models()
    
    def _initialize_models(self):
        """Initialize all AI/ML models"""
        try:
            # Vulnerability severity prediction model
            self._init_severity_model()
            
            # Exploit probability prediction model
            self._init_exploit_model()
            
            # False positive detection model
            self._init_false_positive_model()
            
            # NLP models for text analysis
            self._init_nlp_models()
            
            # Risk scoring model
            self._init_risk_model()
            
            self.logger.info("All AI models initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Error initializing AI models: {e}")
    
    def _init_severity_model(self):
        """Initialize vulnerability severity prediction model"""
        # Features: port, service, CVE score, description features, etc.
        self.models['severity'] = GradientBoostingClassifier(
            n_estimators=200,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        self.scalers['severity'] = StandardScaler()
    
    def _init_exploit_model(self):
        """Initialize exploit probability prediction model"""
        # Neural network for complex pattern recognition
        self.models['exploit'] = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            activation='relu',
            solver='adam',
            alpha=0.001,
            batch_size='auto',
            learning_rate='constant',
            learning_rate_init=0.001,
            max_iter=500,
            random_state=42
        )
        self.scalers['exploit'] = StandardScaler()
    
    def _init_false_positive_model(self):
        """Initialize false positive detection model"""
        self.models['false_positive'] = RandomForestClassifier(
            n_estimators=300,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42
        )
        self.scalers['false_positive'] = StandardScaler()
    
    def _init_nlp_models(self):
        """Initialize NLP models for vulnerability text analysis"""
        try:
            # BERT model for vulnerability classification
            self.nlp_models['classifier'] = pipeline(
                "text-classification",
                model="microsoft/DialoGPT-medium",
                return_all_scores=True
            )
            
            # Vulnerability description embedding model
            self.nlp_models['embeddings'] = AutoModel.from_pretrained(
                "sentence-transformers/all-MiniLM-L6-v2"
            )
            self.nlp_models['tokenizer'] = AutoTokenizer.from_pretrained(
                "sentence-transformers/all-MiniLM-L6-v2"
            )
            
        except Exception as e:
            self.logger.warning(f"NLP models not available: {e}")
    
    def _init_risk_model(self):
        """Initialize comprehensive risk scoring model"""
        # Deep neural network for risk assessment
        self.models['risk'] = tf.keras.Sequential([
            tf.keras.layers.Dense(512, activation='relu', input_shape=(50,)),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(256, activation='relu'),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.models['risk'].compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
    
    async def analyze_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Perform comprehensive AI analysis on discovered vulnerabilities"""
        if not vulnerabilities:
            return {"analysis": "No vulnerabilities to analyze"}
        
        analysis_results = {
            "total_vulnerabilities": len(vulnerabilities),
            "ai_analysis": {},
            "predictions": {},
            "recommendations": [],
            "risk_score": 0.0,
            "priority_vulnerabilities": [],
            "false_positive_candidates": []
        }
        
        try:
            # Extract features from vulnerabilities
            features_df = self._extract_features(vulnerabilities)
            
            # Predict severity levels
            severity_predictions = await self._predict_severity(features_df)
            analysis_results["predictions"]["severity"] = severity_predictions
            
            # Predict exploit probability
            exploit_predictions = await self._predict_exploit_probability(features_df)
            analysis_results["predictions"]["exploit_probability"] = exploit_predictions
            
            # Detect potential false positives
            false_positives = await self._detect_false_positives(features_df)
            analysis_results["false_positive_candidates"] = false_positives
            
            # Generate comprehensive risk score
            risk_score = await self._calculate_risk_score(features_df, vulnerabilities)
            analysis_results["risk_score"] = risk_score
            
            # Identify priority vulnerabilities
            priority_vulns = await self._identify_priority_vulnerabilities(
                vulnerabilities, severity_predictions, exploit_predictions
            )
            analysis_results["priority_vulnerabilities"] = priority_vulns
            
            # Generate AI-powered recommendations
            recommendations = await self._generate_recommendations(vulnerabilities, analysis_results)
            analysis_results["recommendations"] = recommendations
            
            # Perform NLP analysis on vulnerability descriptions
            nlp_analysis = await self._analyze_vulnerability_descriptions(vulnerabilities)
            analysis_results["ai_analysis"]["nlp_insights"] = nlp_analysis
            
            self.logger.info(f"AI analysis completed for {len(vulnerabilities)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Error in AI vulnerability analysis: {e}")
            analysis_results["error"] = str(e)
        
        return analysis_results
    
    def _extract_features(self, vulnerabilities: List[Dict[str, Any]]) -> pd.DataFrame:
        """Extract numerical features from vulnerability data for ML models"""
        features = []
        
        for vuln in vulnerabilities:
            feature_vector = {
                # Basic features
                'port': int(vuln.get('port', 0)),
                'severity_score': self._severity_to_score(vuln.get('severity', 'low')),
                'cvss_score': float(vuln.get('cvss_score', 0.0)),
                
                # Service features
                'service_http': 1 if 'http' in vuln.get('service', '').lower() else 0,
                'service_ssh': 1 if 'ssh' in vuln.get('service', '').lower() else 0,
                'service_ftp': 1 if 'ftp' in vuln.get('service', '').lower() else 0,
                'service_db': 1 if any(db in vuln.get('service', '').lower() 
                                     for db in ['mysql', 'postgres', 'mongodb', 'redis']) else 0,
                
                # Vulnerability type features
                'type_injection': 1 if 'injection' in vuln.get('type', '').lower() else 0,
                'type_xss': 1 if 'xss' in vuln.get('type', '').lower() else 0,
                'type_auth': 1 if 'auth' in vuln.get('type', '').lower() else 0,
                'type_disclosure': 1 if 'disclosure' in vuln.get('type', '').lower() else 0,
                
                # Description features
                'desc_length': len(vuln.get('description', '')),
                'desc_has_poc': 1 if 'poc' in vuln.get('description', '').lower() else 0,
                'desc_has_exploit': 1 if 'exploit' in vuln.get('description', '').lower() else 0,
                
                # Tool features
                'tool_nmap': 1 if vuln.get('tool') == 'nmap' else 0,
                'tool_nuclei': 1 if vuln.get('tool') == 'nuclei' else 0,
                'tool_sqlmap': 1 if vuln.get('tool') == 'sqlmap' else 0,
                
                # Time features
                'discovery_time': (datetime.now() - 
                                 datetime.fromisoformat(vuln.get('timestamp', datetime.now().isoformat()))
                                 ).total_seconds() / 3600,  # hours ago
                
                # Context features
                'has_cve': 1 if vuln.get('cve') else 0,
                'confirmed': 1 if vuln.get('confirmed', False) else 0,
            }
            
            features.append(feature_vector)
        
        return pd.DataFrame(features)
    
    def _severity_to_score(self, severity: str) -> float:
        """Convert severity string to numerical score"""
        severity_map = {
            'critical': 4.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'info': 0.0
        }
        return severity_map.get(severity.lower(), 1.0)
    
    async def _predict_severity(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict vulnerability severity using ML model"""
        try:
            # For demo purposes, generate synthetic predictions
            # In production, this would use trained models
            predictions = []
            
            for idx, row in features_df.iterrows():
                # Simulate AI prediction based on features
                base_severity = row['severity_score']
                cvss_influence = row['cvss_score'] / 10.0
                service_risk = (row['service_http'] + row['service_ssh'] + row['service_db']) * 0.2
                
                adjusted_severity = min(4.0, base_severity + cvss_influence + service_risk)
                
                severity_labels = ['info', 'low', 'medium', 'high', 'critical']
                predicted_severity = severity_labels[min(4, int(adjusted_severity))]
                confidence = min(0.95, 0.6 + (adjusted_severity / 4.0) * 0.35)
                
                predictions.append({
                    'vulnerability_id': idx,
                    'predicted_severity': predicted_severity,
                    'confidence': confidence,
                    'ai_score': adjusted_severity
                })
            
            return predictions
            
        except Exception as e:
            self.logger.error(f"Error predicting severity: {e}")
            return []
    
    async def _predict_exploit_probability(self, features_df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Predict exploit probability for vulnerabilities"""
        predictions = []
        
        for idx, row in features_df.iterrows():
            # Calculate exploit probability based on various factors
            base_prob = 0.1
            
            # Service-based risk
            if row['service_http']:
                base_prob += 0.3
            if row['service_ssh']:
                base_prob += 0.2
            if row['service_db']:
                base_prob += 0.4
            
            # Vulnerability type risk
            if row['type_injection']:
                base_prob += 0.4
            if row['type_xss']:
                base_prob += 0.2
            if row['type_auth']:
                base_prob += 0.3
            
            # Description indicators
            if row['desc_has_poc']:
                base_prob += 0.3
            if row['desc_has_exploit']:
                base_prob += 0.4
            
            # CVE and confirmation
            if row['has_cve']:
                base_prob += 0.2
            if row['confirmed']:
                base_prob += 0.1
            
            exploit_prob = min(1.0, base_prob)
            
            predictions.append({
                'vulnerability_id': idx,
                'exploit_probability': exploit_prob,
                'risk_level': 'high' if exploit_prob > 0.7 else 'medium' if exploit_prob > 0.4 else 'low'
            })
        
        return predictions
    
    async def _detect_false_positives(self, features_df: pd.DataFrame) -> List[int]:
        """Detect potential false positive vulnerabilities"""
        false_positive_candidates = []
        
        for idx, row in features_df.iterrows():
            fp_score = 0.0
            
            # Low confidence indicators
            if row['severity_score'] == 0:  # Info level
                fp_score += 0.3
            
            if not row['confirmed']:
                fp_score += 0.2
            
            if not row['has_cve']:
                fp_score += 0.1
            
            if row['desc_length'] < 50:  # Very short description
                fp_score += 0.2
            
            # Tool-specific false positive patterns
            if row['tool_nmap'] and row['port'] == 0:
                fp_score += 0.3
            
            if fp_score > 0.5:  # Threshold for false positive detection
                false_positive_candidates.append(idx)
        
        return false_positive_candidates
    
    async def _calculate_risk_score(self, features_df: pd.DataFrame, vulnerabilities: List[Dict[str, Any]]) -> float:
        """Calculate comprehensive risk score"""
        if features_df.empty:
            return 0.0
        
        # Weighted risk calculation
        severity_weight = 0.4
        exploit_weight = 0.3
        impact_weight = 0.2
        count_weight = 0.1
        
        # Average severity score
        avg_severity = features_df['severity_score'].mean()
        
        # High-risk vulnerability count
        high_risk_count = len(features_df[features_df['severity_score'] >= 3.0])
        
        # Service exposure risk
        exposed_services = (features_df['service_http'].sum() + 
                          features_df['service_ssh'].sum() + 
                          features_df['service_db'].sum())
        
        # Calculate normalized risk score (0-10)
        risk_score = (
            (avg_severity / 4.0) * severity_weight * 10 +
            (high_risk_count / len(features_df)) * exploit_weight * 10 +
            min(1.0, exposed_services / 10.0) * impact_weight * 10 +
            min(1.0, len(vulnerabilities) / 50.0) * count_weight * 10
        )
        
        return min(10.0, risk_score)
    
    async def _identify_priority_vulnerabilities(self, 
                                               vulnerabilities: List[Dict[str, Any]],
                                               severity_predictions: List[Dict[str, Any]],
                                               exploit_predictions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify high-priority vulnerabilities for immediate attention"""
        priority_vulns = []
        
        for i, vuln in enumerate(vulnerabilities):
            severity_pred = severity_predictions[i] if i < len(severity_predictions) else {}
            exploit_pred = exploit_predictions[i] if i < len(exploit_predictions) else {}
            
            priority_score = 0.0
            
            # Severity contribution
            severity = severity_pred.get('predicted_severity', vuln.get('severity', 'low'))
            if severity == 'critical':
                priority_score += 40
            elif severity == 'high':
                priority_score += 30
            elif severity == 'medium':
                priority_score += 15
            
            # Exploit probability contribution
            exploit_prob = exploit_pred.get('exploit_probability', 0.0)
            priority_score += exploit_prob * 30
            
            # Service criticality
            service = vuln.get('service', '').lower()
            if any(critical_service in service for critical_service in ['http', 'ssh', 'db']):
                priority_score += 20
            
            # CVE availability
            if vuln.get('cve'):
                priority_score += 10
            
            if priority_score >= 60:  # High priority threshold
                priority_vulns.append({
                    'vulnerability': vuln,
                    'priority_score': priority_score,
                    'ai_reasoning': self._generate_priority_reasoning(vuln, severity_pred, exploit_pred)
                })
        
        # Sort by priority score
        priority_vulns.sort(key=lambda x: x['priority_score'], reverse=True)
        
        return priority_vulns[:10]  # Top 10 priority vulnerabilities
    
    def _generate_priority_reasoning(self, vuln: Dict[str, Any], 
                                   severity_pred: Dict[str, Any], 
                                   exploit_pred: Dict[str, Any]) -> str:
        """Generate human-readable reasoning for vulnerability prioritization"""
        reasons = []
        
        severity = severity_pred.get('predicted_severity', vuln.get('severity', 'low'))
        if severity in ['critical', 'high']:
            reasons.append(f"High severity ({severity}) vulnerability")
        
        exploit_prob = exploit_pred.get('exploit_probability', 0.0)
        if exploit_prob > 0.7:
            reasons.append("High exploit probability detected")
        
        if vuln.get('cve'):
            reasons.append("Known CVE available")
        
        service = vuln.get('service', '')
        if service:
            reasons.append(f"Affects critical service: {service}")
        
        return "; ".join(reasons) if reasons else "Standard vulnerability assessment"
    
    async def _generate_recommendations(self, vulnerabilities: List[Dict[str, Any]], 
                                      analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate AI-powered remediation recommendations"""
        recommendations = []
        
        # High-level strategic recommendations
        total_vulns = len(vulnerabilities)
        risk_score = analysis_results.get('risk_score', 0.0)
        
        if risk_score > 8.0:
            recommendations.append({
                'type': 'strategic',
                'priority': 'critical',
                'title': 'Immediate Security Assessment Required',
                'description': f'Risk score of {risk_score:.1f}/10 indicates critical security issues requiring immediate attention.',
                'actions': [
                    'Deploy emergency security patches',
                    'Implement network segmentation',
                    'Enable enhanced monitoring',
                    'Consider temporary service restrictions'
                ]
            })
        
        # Vulnerability-specific recommendations
        priority_vulns = analysis_results.get('priority_vulnerabilities', [])
        for pv in priority_vulns[:5]:  # Top 5 priority vulnerabilities
            vuln = pv['vulnerability']
            vuln_type = vuln.get('type', 'unknown')
            
            if 'injection' in vuln_type.lower():
                recommendations.append({
                    'type': 'technical',
                    'priority': 'high',
                    'title': f'SQL Injection Remediation - {vuln.get("target", "Unknown")}',
                    'description': 'SQL injection vulnerability detected requiring immediate patching.',
                    'actions': [
                        'Implement parameterized queries',
                        'Enable input validation',
                        'Deploy Web Application Firewall',
                        'Review database permissions'
                    ]
                })
        
        # Tool-based recommendations
        tools_used = set(v.get('tool', 'unknown') for v in vulnerabilities)
        if len(tools_used) < 5:
            recommendations.append({
                'type': 'process',
                'priority': 'medium',
                'title': 'Expand Security Testing Coverage',
                'description': f'Only {len(tools_used)} security tools were used. Consider broader testing approach.',
                'actions': [
                    'Integrate additional security scanners',
                    'Implement continuous security testing',
                    'Add manual penetration testing',
                    'Enable automated vulnerability management'
                ]
            })
        
        return recommendations
    
    async def _analyze_vulnerability_descriptions(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability descriptions using NLP"""
        if not self.nlp_models:
            return {"status": "NLP models not available"}
        
        descriptions = [v.get('description', '') for v in vulnerabilities if v.get('description')]
        
        if not descriptions:
            return {"status": "No descriptions to analyze"}
        
        try:
            # Analyze sentiment and classify descriptions
            analysis = {
                'common_keywords': self._extract_common_keywords(descriptions),
                'severity_distribution': self._analyze_severity_language(descriptions),
                'exploit_indicators': self._find_exploit_indicators(descriptions),
                'technical_complexity': self._assess_technical_complexity(descriptions)
            }
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"NLP analysis error: {e}")
            return {"error": str(e)}
    
    def _extract_common_keywords(self, descriptions: List[str]) -> List[Dict[str, Any]]:
        """Extract and rank common keywords from vulnerability descriptions"""
        from collections import Counter
        import re
        
        # Simple keyword extraction (in production, use more sophisticated NLP)
        all_text = ' '.join(descriptions).lower()
        words = re.findall(r'\b\w+\b', all_text)
        
        # Filter out common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'being', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should'}
        filtered_words = [word for word in words if word not in stop_words and len(word) > 2]
        
        keyword_counts = Counter(filtered_words)
        
        return [{'keyword': word, 'frequency': count} 
                for word, count in keyword_counts.most_common(20)]
    
    def _analyze_severity_language(self, descriptions: List[str]) -> Dict[str, int]:
        """Analyze language patterns associated with different severity levels"""
        severity_indicators = {
            'critical': ['critical', 'severe', 'remote code execution', 'rce', 'privilege escalation'],
            'high': ['high', 'dangerous', 'exploit', 'compromise', 'bypass'],
            'medium': ['medium', 'moderate', 'leak', 'disclosure', 'weakness'],
            'low': ['low', 'minor', 'information', 'limited', 'potential']
        }
        
        severity_counts = {level: 0 for level in severity_indicators}
        
        for desc in descriptions:
            desc_lower = desc.lower()
            for level, indicators in severity_indicators.items():
                if any(indicator in desc_lower for indicator in indicators):
                    severity_counts[level] += 1
        
        return severity_counts
    
    def _find_exploit_indicators(self, descriptions: List[str]) -> List[str]:
        """Find indicators of available exploits in descriptions"""
        exploit_indicators = [
            'exploit available', 'proof of concept', 'poc', 'metasploit',
            'exploit-db', 'public exploit', 'working exploit', 'exploit code'
        ]
        
        found_indicators = []
        for desc in descriptions:
            desc_lower = desc.lower()
            for indicator in exploit_indicators:
                if indicator in desc_lower:
                    found_indicators.append(indicator)
        
        return list(set(found_indicators))
    
    def _assess_technical_complexity(self, descriptions: List[str]) -> Dict[str, float]:
        """Assess technical complexity of vulnerabilities based on descriptions"""
        complexity_indicators = {
            'high': ['buffer overflow', 'memory corruption', 'race condition', 'format string'],
            'medium': ['sql injection', 'cross-site scripting', 'directory traversal'],
            'low': ['default credentials', 'information disclosure', 'weak configuration']
        }
        
        complexity_scores = {level: 0 for level in complexity_indicators}
        total_descriptions = len(descriptions)
        
        for desc in descriptions:
            desc_lower = desc.lower()
            for level, indicators in complexity_indicators.items():
                if any(indicator in desc_lower for indicator in indicators):
                    complexity_scores[level] += 1
        
        # Convert to percentages
        return {level: (count / total_descriptions) * 100 
                for level, count in complexity_scores.items()}

class PluginManager:
    """Advanced plugin management system"""
    
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
        
        # AI analyzer
        self.ai_analyzer = AIVulnerabilityAnalyzer(config_manager)
        
        # Initialize plugins
        self._discover_and_load_plugins()
    
    def _discover_and_load_plugins(self):
        """Discover and load all available plugins"""
        self.logger.info("Discovering security scanner plugins...")
        
        for plugin_dir in self.plugin_dirs:
            if not plugin_dir.exists():
                plugin_dir.mkdir(parents=True, exist_ok=True)
                continue
            
            for plugin_file in plugin_dir.glob("*.py"):
                if plugin_file.name.startswith("__"):
                    continue
                
                try:
                    self._load_plugin(plugin_file)
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {plugin_file}: {e}")
        
        self.logger.info(f"Loaded {len(self.plugins)} plugins")
    
    def _load_plugin(self, plugin_file: Path):
        """Load a single plugin from file"""
        module_name = plugin_file.stem
        
        # Load module
        spec = importlib.util.spec_from_file_location(module_name, plugin_file)
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
        plugin = plugin_class(self.config_manager)
        plugin_info = plugin.get_info()
        
        plugin_name = plugin_info.get('name', module_name)
        
        self.plugins[plugin_name] = plugin
        self.plugin_metadata[plugin_name] = plugin_info
        
        self.logger.info(f"Loaded plugin: {plugin_name} v{plugin_info.get('version', 'unknown')}")
    
    def get_available_plugins(self) -> Dict[str, Dict[str, Any]]:
        """Get list of all available plugins with their metadata"""
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
            
            # Add plugin metadata to results
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
        
        # Aggregate vulnerabilities for AI analysis
        all_vulnerabilities = []
        for plugin_result in results.values():
            if 'vulnerabilities' in plugin_result:
                all_vulnerabilities.extend(plugin_result['vulnerabilities'])
        
        # Perform AI analysis
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
            dest_dir = None
            for plugin_dir in self.plugin_dirs:
                if plugin_type in str(plugin_dir):
                    dest_dir = plugin_dir
                    break
            
            if not dest_dir:
                dest_dir = self.plugin_dirs[-1]  # Use custom_plugins as default
            
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
    
    def uninstall_plugin(self, plugin_name: str) -> bool:
        """Uninstall a plugin"""
        try:
            if plugin_name not in self.plugins:
                return False
            
            # Remove from memory
            del self.plugins[plugin_name]
            del self.plugin_metadata[plugin_name]
            
            # Remove plugin file (optional - for custom plugins only)
            for plugin_dir in self.plugin_dirs:
                if "custom" in str(plugin_dir):
                    plugin_file = plugin_dir / f"{plugin_name}.py"
                    if plugin_file.exists():
                        plugin_file.unlink()
                        break
            
            self.logger.info(f"Plugin uninstalled: {plugin_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to uninstall plugin: {e}")
            return False
    
    def get_plugin_options(self, plugin_name: str) -> Dict[str, Any]:
        """Get available options for a plugin"""
        if plugin_name not in self.plugins:
            return {}
        
        return self.plugins[plugin_name].get_scan_options()

# Example plugin implementations would be created in separate files