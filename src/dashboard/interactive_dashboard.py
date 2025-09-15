"""
Advanced Interactive Security Dashboard
Real-time monitoring, SIEM integration, and interactive data visualization
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import websockets
import threading
import time
from pathlib import Path
import sqlite3

from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCharts import *
import plotly.graph_objects as go
import plotly.express as px
from plotly.offline import plot
import plotly.io as pio
import dash
from dash import html, dcc, Input, Output, callback
import pandas as pd
import numpy as np

from core.config_manager import ConfigManager
from core.logger import get_security_logger
from plugins.plugin_manager import PluginManager, AIVulnerabilityAnalyzer

class RealTimeDataManager(QObject):
    """Real-time data management and WebSocket server"""
    
    data_updated = pyqtSignal(dict)
    
    def __init__(self, config_manager: ConfigManager):
        super().__init__()
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
        
        # Data storage
        self.vulnerability_data = []
        self.scan_metrics = {
            'active_scans': 0,
            'completed_scans': 0,
            'vulnerabilities_found': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0
        }
        
        # SQLite database for historical data
        self.db_path = Path("security_scanner.db")
        self._initialize_database()
        
        # WebSocket server for real-time updates
        self.websocket_server = None
        self.websocket_clients = set()
        
        # Start background services
        self._start_websocket_server()
        self._start_data_collection()
    
    def _initialize_database(self):
        """Initialize SQLite database for historical data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT,
                vulnerability_type TEXT,
                severity TEXT,
                tool TEXT,
                description TEXT,
                cvss_score REAL,
                cve TEXT,
                status TEXT DEFAULT 'open'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                target TEXT,
                tools_used TEXT,
                duration INTEGER,
                vulnerabilities_found INTEGER,
                status TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                metric_name TEXT,
                metric_value REAL,
                metric_type TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
        self.logger.info("Database initialized successfully")
    
    def _start_websocket_server(self):
        """Start WebSocket server for real-time communication"""
        def run_server():
            async def handler(websocket, path):
                self.websocket_clients.add(websocket)
                try:
                    await websocket.wait_closed()
                finally:
                    self.websocket_clients.discard(websocket)
            
            start_server = websockets.serve(handler, "localhost", 8765)
            asyncio.get_event_loop().run_until_complete(start_server)
            asyncio.get_event_loop().run_forever()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        self.logger.info("WebSocket server started on ws://localhost:8765")
    
    def _start_data_collection(self):
        """Start background data collection and simulation"""
        def collect_data():
            while True:
                try:
                    # Simulate real-time vulnerability discovery
                    self._simulate_vulnerability_discovery()
                    
                    # Update metrics
                    self._update_scan_metrics()
                    
                    # Broadcast updates to WebSocket clients
                    self._broadcast_updates()
                    
                    # Emit Qt signal for dashboard updates
                    self.data_updated.emit(self.get_current_data())
                    
                    time.sleep(5)  # Update every 5 seconds
                    
                except Exception as e:
                    self.logger.error(f"Error in data collection: {e}")
                    time.sleep(10)
        
        collection_thread = threading.Thread(target=collect_data, daemon=True)
        collection_thread.start()
    
    def _simulate_vulnerability_discovery(self):
        """Simulate real-time vulnerability discovery for demo purposes"""
        import random
        
        vulnerability_types = [
            'SQL Injection', 'Cross-Site Scripting', 'Cross-Site Request Forgery',
            'Buffer Overflow', 'Authentication Bypass', 'Information Disclosure',
            'Directory Traversal', 'Remote Code Execution', 'Privilege Escalation',
            'Weak Cryptography', 'Insecure Configuration', 'Missing Security Headers'
        ]
        
        severities = ['critical', 'high', 'medium', 'low']
        severity_weights = [0.1, 0.2, 0.4, 0.3]  # Lower probability for critical
        
        tools = ['nmap', 'nuclei', 'sqlmap', 'nikto', 'burpsuite', 'zaproxy', 'wapiti']
        
        # Randomly generate new vulnerabilities
        if random.random() < 0.3:  # 30% chance to add vulnerability each cycle
            vuln = {
                'id': len(self.vulnerability_data) + 1,
                'timestamp': datetime.now().isoformat(),
                'target': f"192.168.1.{random.randint(1, 254)}",
                'type': random.choice(vulnerability_types),
                'severity': random.choices(severities, weights=severity_weights)[0],
                'tool': random.choice(tools),
                'description': f"Vulnerability discovered in {random.choice(['web application', 'network service', 'API endpoint'])}",
                'cvss_score': round(random.uniform(1.0, 10.0), 1),
                'cve': f"CVE-2024-{random.randint(1000, 9999)}" if random.random() < 0.4 else None,
                'status': 'open'
            }
            
            self.vulnerability_data.append(vuln)
            
            # Store in database
            self._store_vulnerability(vuln)
    
    def _store_vulnerability(self, vuln: Dict[str, Any]):
        """Store vulnerability in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO vulnerabilities (target, vulnerability_type, severity, tool, 
                                           description, cvss_score, cve, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln['target'], vuln['type'], vuln['severity'], vuln['tool'],
                vuln['description'], vuln['cvss_score'], vuln['cve'], vuln['status']
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing vulnerability: {e}")
    
    def _update_scan_metrics(self):
        """Update real-time scan metrics"""
        # Count vulnerabilities by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for vuln in self.vulnerability_data:
            severity = vuln.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        self.scan_metrics.update({
            'vulnerabilities_found': len(self.vulnerability_data),
            'critical_count': severity_counts['critical'],
            'high_count': severity_counts['high'],
            'medium_count': severity_counts['medium'],
            'low_count': severity_counts['low'],
            'active_scans': max(0, 5 - (len(self.vulnerability_data) % 6)),  # Simulate active scans
            'completed_scans': len(self.vulnerability_data) // 5
        })
        
        # Store metrics in database
        self._store_metrics()
    
    def _store_metrics(self):
        """Store metrics in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for metric_name, metric_value in self.scan_metrics.items():
                cursor.execute('''
                    INSERT INTO security_metrics (metric_name, metric_value, metric_type)
                    VALUES (?, ?, ?)
                ''', (metric_name, float(metric_value), 'scan_metric'))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error storing metrics: {e}")
    
    async def _broadcast_updates(self):
        """Broadcast updates to WebSocket clients"""
        if not self.websocket_clients:
            return
        
        update_data = {
            'type': 'vulnerability_update',
            'timestamp': datetime.now().isoformat(),
            'metrics': self.scan_metrics,
            'latest_vulnerabilities': self.vulnerability_data[-5:] if len(self.vulnerability_data) >= 5 else self.vulnerability_data
        }
        
        # Send to all connected clients
        disconnected_clients = set()
        for client in self.websocket_clients:
            try:
                await client.send(json.dumps(update_data))
            except websockets.exceptions.ConnectionClosed:
                disconnected_clients.add(client)
        
        # Remove disconnected clients
        self.websocket_clients -= disconnected_clients
    
    def get_current_data(self) -> Dict[str, Any]:
        """Get current dashboard data"""
        return {
            'metrics': self.scan_metrics,
            'vulnerabilities': self.vulnerability_data,
            'timestamp': datetime.now().isoformat()
        }
    
    def get_historical_data(self, days: int = 7) -> Dict[str, Any]:
        """Get historical data for analysis"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get vulnerability trends
            vuln_df = pd.read_sql_query('''
                SELECT DATE(timestamp) as date, severity, COUNT(*) as count
                FROM vulnerabilities 
                WHERE timestamp >= date('now', '-{} days')
                GROUP BY DATE(timestamp), severity
            '''.format(days), conn)
            
            # Get metrics trends
            metrics_df = pd.read_sql_query('''
                SELECT DATE(timestamp) as date, metric_name, AVG(metric_value) as value
                FROM security_metrics
                WHERE timestamp >= date('now', '-{} days')
                GROUP BY DATE(timestamp), metric_name
            '''.format(days), conn)
            
            conn.close()
            
            return {
                'vulnerability_trends': vuln_df.to_dict('records'),
                'metrics_trends': metrics_df.to_dict('records')
            }
            
        except Exception as e:
            self.logger.error(f"Error getting historical data: {e}")
            return {'vulnerability_trends': [], 'metrics_trends': []}

class DashboardApp:
    """Dash web application for interactive dashboard"""
    
    def __init__(self, data_manager: RealTimeDataManager):
        self.data_manager = data_manager
        self.app = dash.Dash(__name__)
        self.setup_layout()
        self.setup_callbacks()
    
    def setup_layout(self):
        """Setup Dash application layout"""
        self.app.layout = html.Div([
            # Header
            html.Div([
                html.H1("Security Scanner Pro - Real-Time Dashboard", 
                       style={'textAlign': 'center', 'color': '#2c3e50', 'marginBottom': '30px'}),
                html.Div(id='last-update', style={'textAlign': 'center', 'color': '#7f8c8d'})
            ], style={'padding': '20px', 'backgroundColor': '#ecf0f1'}),
            
            # Metrics Cards
            html.Div([
                html.Div([
                    html.H3(id='vulnerabilities-count', style={'color': '#e74c3c'}),
                    html.P("Total Vulnerabilities", style={'margin': '0'})
                ], className='metric-card', style={
                    'backgroundColor': 'white', 'padding': '20px', 'margin': '10px',
                    'borderRadius': '10px', 'boxShadow': '0 2px 10px rgba(0,0,0,0.1)',
                    'textAlign': 'center', 'width': '200px', 'display': 'inline-block'
                }),
                
                html.Div([
                    html.H3(id='critical-count', style={'color': '#c0392b'}),
                    html.P("Critical Issues", style={'margin': '0'})
                ], className='metric-card', style={
                    'backgroundColor': 'white', 'padding': '20px', 'margin': '10px',
                    'borderRadius': '10px', 'boxShadow': '0 2px 10px rgba(0,0,0,0.1)',
                    'textAlign': 'center', 'width': '200px', 'display': 'inline-block'
                }),
                
                html.Div([
                    html.H3(id='active-scans', style={'color': '#3498db'}),
                    html.P("Active Scans", style={'margin': '0'})
                ], className='metric-card', style={
                    'backgroundColor': 'white', 'padding': '20px', 'margin': '10px',
                    'borderRadius': '10px', 'boxShadow': '0 2px 10px rgba(0,0,0,0.1)',
                    'textAlign': 'center', 'width': '200px', 'display': 'inline-block'
                }),
                
                html.Div([
                    html.H3(id='completed-scans', style={'color': '#27ae60'}),
                    html.P("Completed Scans", style={'margin': '0'})
                ], className='metric-card', style={
                    'backgroundColor': 'white', 'padding': '20px', 'margin': '10px',
                    'borderRadius': '10px', 'boxShadow': '0 2px 10px rgba(0,0,0,0.1)',
                    'textAlign': 'center', 'width': '200px', 'display': 'inline-block'
                })
            ], style={'textAlign': 'center', 'padding': '20px'}),
            
            # Charts Row 1
            html.Div([
                html.Div([
                    dcc.Graph(id='severity-pie-chart')
                ], style={'width': '50%', 'display': 'inline-block', 'padding': '10px'}),
                
                html.Div([
                    dcc.Graph(id='vulnerability-timeline')
                ], style={'width': '50%', 'display': 'inline-block', 'padding': '10px'})
            ]),
            
            # Charts Row 2
            html.Div([
                html.Div([
                    dcc.Graph(id='tool-performance-chart')
                ], style={'width': '50%', 'display': 'inline-block', 'padding': '10px'}),
                
                html.Div([
                    dcc.Graph(id='vulnerability-heatmap')
                ], style={'width': '50%', 'display': 'inline-block', 'padding': '10px'})
            ]),
            
            # Recent Vulnerabilities Table
            html.Div([
                html.H3("Recent Vulnerabilities", style={'color': '#2c3e50', 'marginTop': '30px'}),
                html.Div(id='recent-vulnerabilities-table')
            ], style={'padding': '20px'}),
            
            # Auto-refresh component
            dcc.Interval(
                id='interval-component',
                interval=5000,  # Update every 5 seconds
                n_intervals=0
            )
        ])
    
    def setup_callbacks(self):
        """Setup Dash callbacks for interactivity"""
        
        @self.app.callback(
            [Output('vulnerabilities-count', 'children'),
             Output('critical-count', 'children'),
             Output('active-scans', 'children'),
             Output('completed-scans', 'children'),
             Output('last-update', 'children')],
            [Input('interval-component', 'n_intervals')]
        )
        def update_metrics(n):
            data = self.data_manager.get_current_data()
            metrics = data['metrics']
            
            return (
                str(metrics['vulnerabilities_found']),
                str(metrics['critical_count']),
                str(metrics['active_scans']),
                str(metrics['completed_scans']),
                f"Last updated: {datetime.now().strftime('%H:%M:%S')}"
            )
        
        @self.app.callback(
            Output('severity-pie-chart', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_severity_chart(n):
            data = self.data_manager.get_current_data()
            metrics = data['metrics']
            
            fig = go.Figure(data=[go.Pie(
                labels=['Critical', 'High', 'Medium', 'Low'],
                values=[metrics['critical_count'], metrics['high_count'], 
                       metrics['medium_count'], metrics['low_count']],
                marker_colors=['#c0392b', '#e67e22', '#f39c12', '#27ae60'],
                hole=0.3
            )])
            
            fig.update_layout(
                title="Vulnerability Severity Distribution",
                annotations=[dict(text='Vulnerabilities', x=0.5, y=0.5, font_size=16, showarrow=False)]
            )
            
            return fig
        
        @self.app.callback(
            Output('vulnerability-timeline', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_timeline_chart(n):
            data = self.data_manager.get_current_data()
            vulnerabilities = data['vulnerabilities']
            
            # Group by hour for timeline
            timeline_data = {}
            for vuln in vulnerabilities[-50:]:  # Last 50 vulnerabilities
                timestamp = datetime.fromisoformat(vuln['timestamp'])
                hour_key = timestamp.strftime('%H:%M')
                
                if hour_key not in timeline_data:
                    timeline_data[hour_key] = 0
                timeline_data[hour_key] += 1
            
            hours = list(timeline_data.keys())
            counts = list(timeline_data.values())
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=hours, y=counts,
                mode='lines+markers',
                name='Vulnerabilities Discovered',
                line=dict(color='#e74c3c', width=2),
                marker=dict(size=6)
            ))
            
            fig.update_layout(
                title="Vulnerability Discovery Timeline",
                xaxis_title="Time",
                yaxis_title="Count",
                showlegend=False
            )
            
            return fig
        
        @self.app.callback(
            Output('tool-performance-chart', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_tool_performance(n):
            data = self.data_manager.get_current_data()
            vulnerabilities = data['vulnerabilities']
            
            # Count vulnerabilities by tool
            tool_counts = {}
            for vuln in vulnerabilities:
                tool = vuln.get('tool', 'unknown')
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
            
            tools = list(tool_counts.keys())
            counts = list(tool_counts.values())
            
            fig = go.Figure(data=[go.Bar(
                x=tools, y=counts,
                marker_color='#3498db'
            )])
            
            fig.update_layout(
                title="Tool Performance (Vulnerabilities Found)",
                xaxis_title="Security Tool",
                yaxis_title="Vulnerabilities Found"
            )
            
            return fig
        
        @self.app.callback(
            Output('vulnerability-heatmap', 'figure'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_heatmap(n):
            # Generate sample heatmap data
            targets = [f"192.168.1.{i}" for i in range(1, 11)]
            vuln_types = ['SQL Injection', 'XSS', 'CSRF', 'RCE', 'Auth Bypass']
            
            # Create random heatmap data
            z_data = np.random.randint(0, 10, size=(len(vuln_types), len(targets)))
            
            fig = go.Figure(data=go.Heatmap(
                z=z_data,
                x=targets,
                y=vuln_types,
                colorscale='Reds'
            ))
            
            fig.update_layout(
                title="Vulnerability Heat Map (By Target & Type)",
                xaxis_title="Target IP",
                yaxis_title="Vulnerability Type"
            )
            
            return fig
        
        @self.app.callback(
            Output('recent-vulnerabilities-table', 'children'),
            [Input('interval-component', 'n_intervals')]
        )
        def update_vulnerabilities_table(n):
            data = self.data_manager.get_current_data()
            vulnerabilities = data['vulnerabilities'][-10:]  # Last 10 vulnerabilities
            
            if not vulnerabilities:
                return html.P("No vulnerabilities found.")
            
            table_header = [
                html.Thead([
                    html.Tr([
                        html.Th("Time"),
                        html.Th("Target"),
                        html.Th("Type"),
                        html.Th("Severity"),
                        html.Th("Tool"),
                        html.Th("CVSS")
                    ])
                ])
            ]
            
            table_rows = []
            for vuln in reversed(vulnerabilities):
                timestamp = datetime.fromisoformat(vuln['timestamp'])
                severity_color = {
                    'critical': '#c0392b',
                    'high': '#e67e22', 
                    'medium': '#f39c12',
                    'low': '#27ae60'
                }.get(vuln['severity'], '#7f8c8d')
                
                row = html.Tr([
                    html.Td(timestamp.strftime('%H:%M:%S')),
                    html.Td(vuln['target']),
                    html.Td(vuln['type']),
                    html.Td(vuln['severity'].upper(), style={'color': severity_color, 'fontWeight': 'bold'}),
                    html.Td(vuln['tool']),
                    html.Td(vuln.get('cvss_score', 'N/A'))
                ])
                table_rows.append(row)
            
            table_body = [html.Tbody(table_rows)]
            
            return html.Table(
                table_header + table_body,
                style={'width': '100%', 'borderCollapse': 'collapse'},
                className='table table-striped'
            )
    
    def run(self, host='127.0.0.1', port=8050, debug=False):
        """Run the Dash application"""
        self.app.run_server(host=host, port=port, debug=debug)

class InteractiveDashboardWidget(QWidget):
    """Qt widget containing the interactive dashboard"""
    
    def __init__(self, config_manager: ConfigManager, plugin_manager: PluginManager):
        super().__init__()
        self.config_manager = config_manager
        self.plugin_manager = plugin_manager
        self.logger = get_security_logger(__name__)
        
        # Initialize data manager
        self.data_manager = RealTimeDataManager(config_manager)
        
        # Initialize Dash app
        self.dash_app = DashboardApp(self.data_manager)
        
        # Setup UI
        self.setup_ui()
        
        # Start Dash server
        self.start_dashboard_server()
    
    def setup_ui(self):
        """Setup the Qt widget UI"""
        layout = QVBoxLayout(self)
        
        # Control panel
        control_panel = QHBoxLayout()
        
        self.start_btn = QPushButton("Start Real-Time Monitoring")
        self.start_btn.clicked.connect(self.start_monitoring)
        control_panel.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("Stop Monitoring")
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.stop_btn.setEnabled(False)
        control_panel.addWidget(self.stop_btn)
        
        control_panel.addStretch()
        
        self.refresh_btn = QPushButton("Force Refresh")
        self.refresh_btn.clicked.connect(self.force_refresh)
        control_panel.addWidget(self.refresh_btn)
        
        layout.addLayout(control_panel)
        
        # Web view for dashboard
        self.web_view = QWebEngineView()
        self.web_view.setUrl(QUrl("http://127.0.0.1:8050"))
        layout.addWidget(self.web_view)
        
        # Status bar
        self.status_label = QLabel("Dashboard initializing...")
        layout.addWidget(self.status_label)
        
        # Connect data manager signals
        self.data_manager.data_updated.connect(self.on_data_updated)
    
    def start_dashboard_server(self):
        """Start the Dash server in a separate thread"""
        def run_dash():
            try:
                self.dash_app.run(host='127.0.0.1', port=8050, debug=False)
            except Exception as e:
                self.logger.error(f"Error running dashboard server: {e}")
        
        server_thread = threading.Thread(target=run_dash, daemon=True)
        server_thread.start()
        
        # Wait a moment for server to start, then load the page
        QTimer.singleShot(3000, lambda: self.web_view.reload())
    
    def start_monitoring(self):
        """Start real-time monitoring"""
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Real-time monitoring active")
        self.logger.info("Real-time monitoring started")
    
    def stop_monitoring(self):
        """Stop real-time monitoring"""
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Monitoring stopped")
        self.logger.info("Real-time monitoring stopped")
    
    def force_refresh(self):
        """Force refresh the dashboard"""
        self.web_view.reload()
        self.status_label.setText("Dashboard refreshed")
    
    def on_data_updated(self, data):
        """Handle data updates from the data manager"""
        metrics = data['metrics']
        self.status_label.setText(
            f"Live: {metrics['vulnerabilities_found']} vulnerabilities, "
            f"{metrics['active_scans']} active scans"
        )

class SIEMIntegration:
    """Integration with Security Information and Event Management systems"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = get_security_logger(__name__)
        
        # SIEM configurations
        self.siem_configs = {
            'splunk': {
                'host': 'localhost',
                'port': 8089,
                'username': 'admin',
                'password': 'password',
                'index': 'security_scanner'
            },
            'elastic': {
                'host': 'localhost',
                'port': 9200,
                'index': 'security-scanner-logs'
            },
            'qradar': {
                'host': 'qradar-console',
                'port': 443,
                'token': 'your-api-token'
            }
        }
    
    async def send_to_splunk(self, event_data: Dict[str, Any]):
        """Send security events to Splunk"""
        try:
            import splunklib.client as client
            
            config = self.siem_configs['splunk']
            service = client.connect(
                host=config['host'],
                port=config['port'],
                username=config['username'],
                password=config['password']
            )
            
            index = service.indexes[config['index']]
            index.submit(json.dumps(event_data))
            
            self.logger.info("Event sent to Splunk successfully")
            
        except Exception as e:
            self.logger.error(f"Error sending event to Splunk: {e}")
    
    async def send_to_elasticsearch(self, event_data: Dict[str, Any]):
        """Send security events to Elasticsearch"""
        try:
            from elasticsearch import Elasticsearch
            
            config = self.siem_configs['elastic']
            es = Elasticsearch([{'host': config['host'], 'port': config['port']}])
            
            es.index(
                index=config['index'],
                body=event_data,
                doc_type='security_event'
            )
            
            self.logger.info("Event sent to Elasticsearch successfully")
            
        except Exception as e:
            self.logger.error(f"Error sending event to Elasticsearch: {e}")
    
    async def send_to_qradar(self, event_data: Dict[str, Any]):
        """Send security events to IBM QRadar"""
        try:
            import requests
            
            config = self.siem_configs['qradar']
            headers = {
                'SEC': config['token'],
                'Content-Type': 'application/json'
            }
            
            url = f"https://{config['host']}:{config['port']}/api/siem/offenses"
            
            response = requests.post(url, json=event_data, headers=headers, verify=False)
            response.raise_for_status()
            
            self.logger.info("Event sent to QRadar successfully")
            
        except Exception as e:
            self.logger.error(f"Error sending event to QRadar: {e}")
    
    async def send_vulnerability_alert(self, vulnerability: Dict[str, Any]):
        """Send vulnerability alert to all configured SIEM systems"""
        event_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'vulnerability_discovered',
            'source': 'security_scanner_pro',
            'severity': vulnerability.get('severity', 'unknown'),
            'target': vulnerability.get('target', 'unknown'),
            'vulnerability_type': vulnerability.get('type', 'unknown'),
            'tool': vulnerability.get('tool', 'unknown'),
            'cvss_score': vulnerability.get('cvss_score', 0.0),
            'cve': vulnerability.get('cve'),
            'description': vulnerability.get('description', ''),
            'raw_data': vulnerability
        }
        
        # Send to all configured SIEM systems
        tasks = [
            self.send_to_splunk(event_data),
            self.send_to_elasticsearch(event_data),
            self.send_to_qradar(event_data)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)