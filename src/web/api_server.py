#!/usr/bin/env python3
"""
Web API Server for Security Scanner
Provides REST API endpoints for remote scanner management

Author: ReliableSecurity
GitHub: https://github.com/ReliableSecurity
Telegram: @ReliableSecurity
"""

import sys
import os
import asyncio
import uuid
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
import uvicorn

from core.config_manager import ConfigManager
from core.logger import get_security_logger
from plugins.plugin_manager_fixed import PluginManager

# Pydantic models for API
class ScanRequest(BaseModel):
    target: str
    profile: str = "quick"
    tools: Optional[List[str]] = None
    options: Optional[Dict[str, Any]] = None

class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress: int
    target: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    vulnerabilities_found: int = 0
    tools_used: List[str] = []

class VulnerabilityInfo(BaseModel):
    id: str
    type: str
    severity: str
    title: str
    description: str
    target: str
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    solution: Optional[str] = None

class APIResponse(BaseModel):
    success: bool
    message: str
    data: Optional[Any] = None

class WebAPIServer:
    """FastAPI-based web server for security scanner"""
    
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.logger = get_security_logger("web_api")
        self.plugin_manager = PluginManager(config_manager)
        
        # Active scans tracking
        self.active_scans: Dict[str, Dict] = {}
        self.scan_results: Dict[str, Dict] = {}
        
        # WebSocket connections for real-time updates
        self.websocket_connections: List[WebSocket] = []
        
        # Create FastAPI app
        self.app = FastAPI(
            title="Advanced Security Scanner API",
            description="REST API for comprehensive security scanning",
            version="2.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc"
        )
        
        # Configure CORS
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Setup routes
        self._setup_routes()
        
        # Setup static files
        web_static = Path(__file__).parent / "static"
        if web_static.exists():
            self.app.mount("/static", StaticFiles(directory=str(web_static)), name="static")
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/", response_class=HTMLResponse)
        async def dashboard():
            """Serve the main dashboard"""
            return self._get_dashboard_html()
        
        @self.app.get("/api/health")
        async def health_check():
            """Health check endpoint"""
            return APIResponse(
                success=True,
                message="Security Scanner API is running",
                data={
                    "version": "2.0.0",
                    "active_scans": len(self.active_scans),
                    "available_tools": len(self.plugin_manager.get_available_plugins())
                }
            )
        
        @self.app.get("/api/tools")
        async def list_tools():
            """Get list of available security tools"""
            try:
                tools = self.config.get_all_tools()
                enabled_tools = {k: v for k, v in tools.items() if v.get('enabled', False)}
                
                return APIResponse(
                    success=True,
                    message=f"Found {len(enabled_tools)} enabled tools",
                    data=enabled_tools
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/profiles")
        async def list_profiles():
            """Get list of available scan profiles"""
            try:
                profiles = self.config.get_all_profiles()
                return APIResponse(
                    success=True,
                    message=f"Found {len(profiles)} profiles",
                    data=profiles
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.post("/api/scan")
        async def start_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
            """Start a new security scan"""
            try:
                scan_id = str(uuid.uuid4())
                
                # Validate target
                if not scan_request.target:
                    raise HTTPException(status_code=400, detail="Target is required")
                
                # Create scan entry
                scan_info = {
                    "scan_id": scan_id,
                    "target": scan_request.target,
                    "profile": scan_request.profile,
                    "tools": scan_request.tools or [],
                    "options": scan_request.options or {},
                    "status": "queued",
                    "progress": 0,
                    "started_at": datetime.utcnow(),
                    "vulnerabilities": [],
                    "logs": []
                }
                
                self.active_scans[scan_id] = scan_info
                
                # Start scan in background
                background_tasks.add_task(self._execute_scan, scan_id, scan_info)
                
                self.logger.info(f"Started scan {scan_id} for target {scan_request.target}")
                
                return APIResponse(
                    success=True,
                    message="Scan started successfully",
                    data={"scan_id": scan_id, "status": "queued"}
                )
                
            except Exception as e:
                self.logger.error(f"Failed to start scan: {e}")
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/scan/{scan_id}")
        async def get_scan_status(scan_id: str):
            """Get status of a specific scan"""
            if scan_id not in self.active_scans and scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            scan_info = self.active_scans.get(scan_id) or self.scan_results.get(scan_id)
            
            return APIResponse(
                success=True,
                message="Scan status retrieved",
                data=scan_info
            )
        
        @self.app.get("/api/scans")
        async def list_scans():
            """Get list of all scans"""
            all_scans = {**self.active_scans, **self.scan_results}
            
            return APIResponse(
                success=True,
                message=f"Found {len(all_scans)} scans",
                data=list(all_scans.values())
            )
        
        @self.app.delete("/api/scan/{scan_id}")
        async def stop_scan(scan_id: str):
            """Stop an active scan"""
            if scan_id not in self.active_scans:
                raise HTTPException(status_code=404, detail="Active scan not found")
            
            # Mark scan as stopped
            self.active_scans[scan_id]["status"] = "stopped"
            self.logger.info(f"Stopped scan {scan_id}")
            
            return APIResponse(
                success=True,
                message="Scan stopped successfully"
            )
        
        @self.app.get("/api/scan/{scan_id}/report")
        async def get_scan_report(scan_id: str, format: str = "json"):
            """Get scan report in specified format"""
            if scan_id not in self.scan_results:
                raise HTTPException(status_code=404, detail="Scan results not found")
            
            scan_data = self.scan_results[scan_id]
            
            if format.lower() == "html":
                # Generate HTML report
                try:
                    from reports.report_generator import ReportGenerator
                    report_gen = ReportGenerator(self.config)
                    
                    report_path = report_gen.generate_html_report(scan_data, f"scan_{scan_id}.html")
                    return FileResponse(
                        report_path,
                        media_type="text/html",
                        filename=f"security_report_{scan_id}.html"
                    )
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")
            
            # Default JSON format
            return APIResponse(
                success=True,
                message="Scan report retrieved",
                data=scan_data
            )
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            """WebSocket endpoint for real-time updates"""
            await websocket.accept()
            self.websocket_connections.append(websocket)
            
            try:
                while True:
                    # Keep connection alive and send updates
                    await websocket.receive_text()
            except WebSocketDisconnect:
                self.websocket_connections.remove(websocket)
    
    async def _execute_scan(self, scan_id: str, scan_info: Dict):
        """Execute security scan in background"""
        try:
            self.active_scans[scan_id]["status"] = "running"
            self.active_scans[scan_id]["progress"] = 10
            
            await self._broadcast_scan_update(scan_id, "Scan started")
            
            # Get tools to use
            tools_to_use = scan_info["tools"]
            if not tools_to_use:
                # Use profile default tools
                profile = self.config.get_profile(scan_info["profile"])
                tools_to_use = profile.get("tools", ["nmap", "nuclei"])
            
            # Execute tools
            vulnerabilities = []
            total_tools = len(tools_to_use)
            
            for i, tool in enumerate(tools_to_use):
                if self.active_scans[scan_id]["status"] == "stopped":
                    break
                
                self.active_scans[scan_id]["progress"] = 20 + (60 * i // total_tools)
                await self._broadcast_scan_update(scan_id, f"Running {tool}")
                
                try:
                    # Simulate tool execution (replace with actual plugin execution)
                    await asyncio.sleep(2)  # Simulate tool runtime
                    
                    # Mock vulnerability data
                    if tool == "nmap":
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "type": "Open Port",
                            "severity": "medium",
                            "title": f"Open port found on {scan_info['target']}",
                            "description": "Port 80 is open and running HTTP service",
                            "target": scan_info['target'],
                            "tool": tool,
                            "cvss_score": 5.0
                        })
                    elif tool == "nuclei":
                        vulnerabilities.append({
                            "id": str(uuid.uuid4()),
                            "type": "Information Disclosure",
                            "severity": "low",
                            "title": "Server information exposed",
                            "description": "Server version information disclosed in headers",
                            "target": scan_info['target'],
                            "tool": tool,
                            "cvss_score": 3.0
                        })
                
                except Exception as e:
                    self.logger.error(f"Tool {tool} failed: {e}")
                    self.active_scans[scan_id]["logs"].append(f"Error in {tool}: {e}")
            
            # AI Analysis
            self.active_scans[scan_id]["progress"] = 85
            await self._broadcast_scan_update(scan_id, "Running AI analysis")
            
            try:
                ai_analysis = await self.plugin_manager.ai_analyzer.analyze_vulnerabilities(vulnerabilities)
                self.active_scans[scan_id]["ai_analysis"] = ai_analysis
            except Exception as e:
                self.logger.error(f"AI analysis failed: {e}")
                self.active_scans[scan_id]["ai_analysis"] = {"error": str(e)}
            
            # Complete scan
            self.active_scans[scan_id]["status"] = "completed"
            self.active_scans[scan_id]["progress"] = 100
            self.active_scans[scan_id]["completed_at"] = datetime.utcnow()
            self.active_scans[scan_id]["vulnerabilities"] = vulnerabilities
            self.active_scans[scan_id]["vulnerabilities_found"] = len(vulnerabilities)
            
            # Move to results
            self.scan_results[scan_id] = self.active_scans[scan_id].copy()
            del self.active_scans[scan_id]
            
            await self._broadcast_scan_update(scan_id, "Scan completed")
            self.logger.info(f"Completed scan {scan_id}")
            
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {e}")
            self.active_scans[scan_id]["status"] = "failed"
            self.active_scans[scan_id]["error"] = str(e)
    
    async def _broadcast_scan_update(self, scan_id: str, message: str):
        """Broadcast scan updates to WebSocket clients"""
        update = {
            "type": "scan_update",
            "scan_id": scan_id,
            "message": message,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        disconnected = []
        for websocket in self.websocket_connections:
            try:
                await websocket.send_text(json.dumps(update))
            except:
                disconnected.append(websocket)
        
        # Clean up disconnected clients
        for ws in disconnected:
            if ws in self.websocket_connections:
                self.websocket_connections.remove(ws)
    
    def _get_dashboard_html(self) -> str:
        """Generate dashboard HTML"""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Security Scanner - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f0f0f; color: #fff; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 1rem; text-align: center; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; }
        .card { background: #1a1a1a; border-radius: 8px; padding: 1.5rem; margin: 1rem 0; border: 1px solid #333; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .btn { background: #667eea; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #5a6fd8; }
        .status { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; }
        .status.running { background: #f39c12; }
        .status.completed { background: #27ae60; }
        .status.failed { background: #e74c3c; }
        .progress { width: 100%; height: 8px; background: #333; border-radius: 4px; overflow: hidden; }
        .progress-bar { height: 100%; background: #667eea; transition: width 0.3s; }
        #scanForm { display: grid; gap: 1rem; }
        #scanForm input, #scanForm select { padding: 0.5rem; border: 1px solid #333; background: #2a2a2a; color: #fff; border-radius: 4px; }
        .log { background: #111; padding: 0.5rem; border-radius: 4px; font-family: monospace; font-size: 0.8rem; max-height: 200px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔐 Advanced Security Scanner</h1>
        <p>Web-based Security Assessment Dashboard</p>
    </div>
    
    <div class="container">
        <div class="grid">
            <div class="card">
                <h2>Start New Scan</h2>
                <form id="scanForm">
                    <input type="text" id="target" placeholder="Target (IP, domain, or range)" required>
                    <select id="profile">
                        <option value="quick">Quick Scan</option>
                        <option value="standard">Standard Scan</option>
                        <option value="comprehensive">Comprehensive Scan</option>
                    </select>
                    <button type="submit" class="btn">🚀 Start Scan</button>
                </form>
            </div>
            
            <div class="card">
                <h2>Scanner Statistics</h2>
                <div id="stats">
                    <p>Active Scans: <span id="activeScans">0</span></p>
                    <p>Completed Scans: <span id="completedScans">0</span></p>
                    <p>Available Tools: <span id="availableTools">0</span></p>
                </div>
            </div>
        </div>
        
        <div class="card">
            <h2>Active Scans</h2>
            <div id="activeScansContainer">
                <p>No active scans</p>
            </div>
        </div>
        
        <div class="card">
            <h2>Recent Scans</h2>
            <div id="recentScansContainer">
                <p>No recent scans</p>
            </div>
        </div>
        
        <div class="card">
            <h2>Real-time Log</h2>
            <div id="realTimeLog" class="log">
                <p>Connecting to scanner...</p>
            </div>
        </div>
    </div>

    <script>
        let websocket = null;
        
        // Connect to WebSocket
        function connectWebSocket() {
            const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
            websocket = new WebSocket(`${protocol}//${window.location.host}/ws`);
            
            websocket.onopen = function() {
                addLog('Connected to scanner');
            };
            
            websocket.onmessage = function(event) {
                const data = JSON.parse(event.data);
                addLog(`[${data.scan_id}] ${data.message}`);
                refreshScans();
            };
            
            websocket.onclose = function() {
                addLog('Connection lost, reconnecting...');
                setTimeout(connectWebSocket, 3000);
            };
        }
        
        // Add log entry
        function addLog(message) {
            const logContainer = document.getElementById('realTimeLog');
            const timestamp = new Date().toLocaleTimeString();
            logContainer.innerHTML += `<div>[${timestamp}] ${message}</div>`;
            logContainer.scrollTop = logContainer.scrollHeight;
        }
        
        // Start scan
        document.getElementById('scanForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const target = document.getElementById('target').value;
            const profile = document.getElementById('profile').value;
            
            try {
                const response = await fetch('/api/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, profile })
                });
                
                const result = await response.json();
                
                if (result.success) {
                    addLog(`Started scan for ${target} (${result.data.scan_id})`);
                    document.getElementById('target').value = '';
                    refreshScans();
                } else {
                    addLog(`Failed to start scan: ${result.message}`);
                }
            } catch (error) {
                addLog(`Error: ${error.message}`);
            }
        });
        
        // Refresh scans
        async function refreshScans() {
            try {
                const response = await fetch('/api/scans');
                const result = await response.json();
                
                if (result.success) {
                    updateScansDisplay(result.data);
                }
            } catch (error) {
                console.error('Failed to refresh scans:', error);
            }
        }
        
        // Update scans display
        function updateScansDisplay(scans) {
            const activeContainer = document.getElementById('activeScansContainer');
            const recentContainer = document.getElementById('recentScansContainer');
            
            const activeScans = scans.filter(s => s.status === 'running' || s.status === 'queued');
            const recentScans = scans.filter(s => s.status === 'completed' || s.status === 'failed').slice(0, 10);
            
            // Update statistics
            document.getElementById('activeScans').textContent = activeScans.length;
            document.getElementById('completedScans').textContent = recentScans.filter(s => s.status === 'completed').length;
            
            // Update active scans
            if (activeScans.length === 0) {
                activeContainer.innerHTML = '<p>No active scans</p>';
            } else {
                activeContainer.innerHTML = activeScans.map(scan => `
                    <div style="border: 1px solid #333; padding: 1rem; margin: 0.5rem 0; border-radius: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong>${scan.target}</strong>
                            <span class="status ${scan.status}">${scan.status}</span>
                        </div>
                        <div>Profile: ${scan.profile}</div>
                        <div class="progress" style="margin: 0.5rem 0;">
                            <div class="progress-bar" style="width: ${scan.progress}%"></div>
                        </div>
                        <div>${scan.progress}% complete</div>
                    </div>
                `).join('');
            }
            
            // Update recent scans
            if (recentScans.length === 0) {
                recentContainer.innerHTML = '<p>No recent scans</p>';
            } else {
                recentContainer.innerHTML = recentScans.map(scan => `
                    <div style="border: 1px solid #333; padding: 1rem; margin: 0.5rem 0; border-radius: 4px;">
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <strong>${scan.target}</strong>
                            <span class="status ${scan.status}">${scan.status}</span>
                        </div>
                        <div>Vulnerabilities: ${scan.vulnerabilities_found || 0}</div>
                        <div>
                            <button class="btn" onclick="downloadReport('${scan.scan_id}', 'json')">JSON Report</button>
                            <button class="btn" onclick="downloadReport('${scan.scan_id}', 'html')">HTML Report</button>
                        </div>
                    </div>
                `).join('');
            }
        }
        
        // Download report
        function downloadReport(scanId, format) {
            window.open(`/api/scan/${scanId}/report?format=${format}`, '_blank');
        }
        
        // Load statistics
        async function loadStats() {
            try {
                const response = await fetch('/api/health');
                const result = await response.json();
                
                if (result.success) {
                    document.getElementById('availableTools').textContent = result.data.available_tools;
                }
            } catch (error) {
                console.error('Failed to load statistics:', error);
            }
        }
        
        // Initialize
        connectWebSocket();
        loadStats();
        refreshScans();
        
        // Auto-refresh every 5 seconds
        setInterval(refreshScans, 5000);
    </script>
</body>
</html>
        """
    
    def start_server(self, host: str = "0.0.0.0", port: int = 8000):
        """Start the web server"""
        self.logger.info(f"Starting web server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port)

if __name__ == "__main__":
    # Create and start server
    config = ConfigManager()
    server = WebAPIServer(config)
    server.start_server()