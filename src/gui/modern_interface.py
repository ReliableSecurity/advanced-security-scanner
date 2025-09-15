"""
Modern Material Design GUI Interface
Advanced PyQt6 implementation with Material Design 3, animations, and 3D visualizations
"""

import sys
import os
try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore import *
    from PyQt6.QtGui import *
    PYQT6_AVAILABLE = True
except ImportError:
    from PyQt5.QtWidgets import *
    from PyQt5.QtCore import *
    from PyQt5.QtGui import *
    PYQT6_AVAILABLE = False

# Optional imports with fallbacks
try:
    if PYQT6_AVAILABLE:
        from PyQt6.QtOpenGL import *
    else:
        from PyQt5.QtOpenGL import *
    OPENGL_AVAILABLE = True
except ImportError:
    OPENGL_AVAILABLE = False
    print("Warning: OpenGL not available, 3D features disabled")

try:
    if PYQT6_AVAILABLE:
        from PyQt6.QtCharts import *
    else:
        from PyQt5.QtChart import *
    CHARTS_AVAILABLE = True
except ImportError:
    CHARTS_AVAILABLE = False
    print("Warning: Charts not available, using basic widgets")
import json
import math
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

# Optional scientific computing imports
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: NumPy not available, using basic calculations")

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    print("Warning: Plotly not available, using basic charts")

try:
    import dash
    from dash import html, dcc, Input, Output
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False
    print("Warning: Dash not available, web dashboard disabled")

class MaterialColors:
    """Material Design 3 Color System"""
    PRIMARY = "#6750A4"
    PRIMARY_CONTAINER = "#EADDFF"
    SECONDARY = "#625B71"
    SECONDARY_CONTAINER = "#E8DEF8"
    TERTIARY = "#7D5260"
    TERTIARY_CONTAINER = "#FFD8E4"
    ERROR = "#BA1A1A"
    ERROR_CONTAINER = "#FFDAD6"
    SURFACE = "#FDF7FF"
    SURFACE_VARIANT = "#E7E0EC"
    SURFACE_DIM = "#DED8E1"
    SURFACE_BRIGHT = "#FDF7FF"
    OUTLINE = "#79747E"
    OUTLINE_VARIANT = "#CAC4D0"
    ON_PRIMARY = "#FFFFFF"
    ON_SECONDARY = "#FFFFFF"
    ON_SURFACE = "#1D1B20"
    ON_SURFACE_VARIANT = "#49454F"

class MaterialAnimations(QPropertyAnimation):
    """Material Design 3 Motion System"""
    
    def __init__(self, target, property_name: str, duration: int = 300):
        super().__init__(target, property_name.encode())
        self.setDuration(duration)
        self.setEasingCurve(QEasingCurve.Type.OutCubic)
    
    @staticmethod
    def create_fade_in(widget: QWidget, duration: int = 300) -> QPropertyAnimation:
        """Create fade in animation"""
        animation = MaterialAnimations(widget, "windowOpacity", duration)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        return animation
    
    @staticmethod
    def create_slide_up(widget: QWidget, distance: int = 50, duration: int = 400) -> QPropertyAnimation:
        """Create slide up animation"""
        animation = MaterialAnimations(widget, "pos", duration)
        start_pos = widget.pos()
        end_pos = QPoint(start_pos.x(), start_pos.y() - distance)
        animation.setStartValue(start_pos)
        animation.setEndValue(end_pos)
        return animation
    
    @staticmethod
    def create_scale_animation(widget: QWidget, scale_factor: float = 1.05, duration: int = 200) -> QPropertyAnimation:
        """Create scale animation effect"""
        animation = MaterialAnimations(widget, "size", duration)
        original_size = widget.size()
        scaled_size = QSize(
            int(original_size.width() * scale_factor),
            int(original_size.height() * scale_factor)
        )
        animation.setStartValue(original_size)
        animation.setEndValue(scaled_size)
        return animation

class ModernCard(QFrame):
    """Material Design Card Component"""
    
    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.title = title
        self.setup_ui()
    
    def setup_ui(self):
        """Setup card UI with Material Design styling"""
        self.setFrameShape(QFrame.Shape.Box)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {MaterialColors.SURFACE};
                border: none;
                border-radius: 16px;
                padding: 16px;
                box-shadow: 0px 2px 8px rgba(0, 0, 0, 0.15);
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        
        if self.title:
            title_label = QLabel(self.title)
            title_label.setStyleSheet(f"""
                QLabel {{
                    font-size: 20px;
                    font-weight: bold;
                    color: {MaterialColors.ON_SURFACE};
                    margin-bottom: 8px;
                }}
            """)
            layout.addWidget(title_label)
        
        self.content_area = QVBoxLayout()
        layout.addLayout(self.content_area)
        
        # Add hover effects
        self.installEventFilter(self)
    
    def eventFilter(self, obj, event):
        """Handle hover effects"""
        if event.type() == QEvent.Type.Enter:
            self.animate_hover_in()
        elif event.type() == QEvent.Type.Leave:
            self.animate_hover_out()
        return super().eventFilter(obj, event)
    
    def animate_hover_in(self):
        """Animate card on hover"""
        self.hover_animation = MaterialAnimations.create_scale_animation(self, 1.02, 200)
        self.hover_animation.start()
    
    def animate_hover_out(self):
        """Animate card on leave"""
        self.hover_animation = MaterialAnimations.create_scale_animation(self, 1.0, 200)
        self.hover_animation.start()

class MaterialButton(QPushButton):
    """Material Design Button with animations"""
    
    def __init__(self, text: str = "", button_type: str = "filled", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self.setup_ui()
    
    def setup_ui(self):
        """Setup button with Material Design styling"""
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(40)
        
        if self.button_type == "filled":
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: {MaterialColors.PRIMARY};
                    color: {MaterialColors.ON_PRIMARY};
                    border: none;
                    border-radius: 20px;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 10px 24px;
                }}
                QPushButton:hover {{
                    background-color: {MaterialColors.PRIMARY_CONTAINER};
                }}
                QPushButton:pressed {{
                    background-color: {MaterialColors.SECONDARY};
                }}
            """)
        elif self.button_type == "outlined":
            self.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {MaterialColors.PRIMARY};
                    border: 2px solid {MaterialColors.OUTLINE};
                    border-radius: 20px;
                    font-size: 14px;
                    font-weight: bold;
                    padding: 10px 24px;
                }}
                QPushButton:hover {{
                    background-color: {MaterialColors.PRIMARY_CONTAINER};
                }}
            """)
    
    def mousePressEvent(self, event):
        """Handle click animation"""
        self.click_animation = MaterialAnimations.create_scale_animation(self, 0.95, 100)
        self.click_animation.finished.connect(self.restore_scale)
        self.click_animation.start()
        super().mousePressEvent(event)
    
    def restore_scale(self):
        """Restore button scale after click"""
        self.restore_animation = MaterialAnimations.create_scale_animation(self, 1.0, 100)
        self.restore_animation.start()

if OPENGL_AVAILABLE:
    class Dashboard3D(QOpenGLWidget):
        """3D Visualization Dashboard using OpenGL"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.vulnerabilities_data = []
            self.rotation_x = 0
            self.rotation_y = 0
            self.rotation_z = 0
            
            # Animation timer
            self.timer = QTimer()
            self.timer.timeout.connect(self.update_rotation)
            self.timer.start(50)  # 50ms for smooth animation
else:
    class Dashboard3D(QWidget):
        """Fallback 2D Dashboard when OpenGL is not available"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.vulnerabilities_data = []
            self.setup_fallback_ui()
        
        def setup_fallback_ui(self):
            layout = QVBoxLayout(self)
            label = QLabel("3D Visualization not available\n(OpenGL not installed)")
            label.setAlignment(Qt.AlignCenter)
            label.setStyleSheet("color: #666; font-size: 14px;")
            layout.addWidget(label)
        
        def set_vulnerabilities_data(self, data: List[Dict[str, Any]]):
            """Fallback method for compatibility"""
            self.vulnerabilities_data = data
    
    def initializeGL(self):
        """Initialize OpenGL settings"""
        glEnable(GL_DEPTH_TEST)
        glClearColor(0.1, 0.1, 0.1, 1.0)
    
    def resizeGL(self, width, height):
        """Handle window resize"""
        glViewport(0, 0, width, height)
        glMatrixMode(GL_PROJECTION)
        glLoadIdentity()
        aspect = width / height if height != 0 else 1
        gluPerspective(45, aspect, 1, 100)
        glMatrixMode(GL_MODELVIEW)
    
    def paintGL(self):
        """Render 3D visualization"""
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT)
        glLoadIdentity()
        
        # Position camera
        glTranslatef(0, 0, -10)
        
        # Apply rotations
        glRotatef(self.rotation_x, 1, 0, 0)
        glRotatef(self.rotation_y, 0, 1, 0)
        glRotatef(self.rotation_z, 0, 0, 1)
        
        # Draw vulnerability network graph in 3D
        self.draw_vulnerability_network()
    
    def draw_vulnerability_network(self):
        """Draw 3D vulnerability network visualization"""
        # Draw nodes (vulnerabilities)
        for i, vuln in enumerate(self.vulnerabilities_data):
            severity = vuln.get('severity', 'low')
            
            # Set color based on severity
            if severity == 'critical':
                glColor3f(1.0, 0.0, 0.0)  # Red
            elif severity == 'high':
                glColor3f(1.0, 0.5, 0.0)  # Orange
            elif severity == 'medium':
                glColor3f(1.0, 1.0, 0.0)  # Yellow
            else:
                glColor3f(0.0, 1.0, 0.0)  # Green
            
            # Position nodes in 3D space
            x = 5 * math.cos(2 * math.pi * i / len(self.vulnerabilities_data))
            y = 5 * math.sin(2 * math.pi * i / len(self.vulnerabilities_data))
            z = (i % 3 - 1) * 2
            
            glPushMatrix()
            glTranslatef(x, y, z)
            
            # Draw sphere for vulnerability
            quadric = gluNewQuadric()
            gluSphere(quadric, 0.3, 20, 20)
            gluDeleteQuadric(quadric)
            
            glPopMatrix()
            
            # Draw connections between related vulnerabilities
            glColor3f(0.3, 0.3, 0.3)
            glBegin(GL_LINES)
            for j in range(i + 1, len(self.vulnerabilities_data)):
                x2 = 5 * math.cos(2 * math.pi * j / len(self.vulnerabilities_data))
                y2 = 5 * math.sin(2 * math.pi * j / len(self.vulnerabilities_data))
                z2 = (j % 3 - 1) * 2
                
                glVertex3f(x, y, z)
                glVertex3f(x2, y2, z2)
            glEnd()
    
    def update_rotation(self):
        """Update rotation for animation"""
        self.rotation_y += 1
        if self.rotation_y >= 360:
            self.rotation_y = 0
        self.update()
    
    def set_vulnerabilities_data(self, data: List[Dict[str, Any]]):
        """Update vulnerability data for visualization"""
        self.vulnerabilities_data = data
        self.update()

class InteractiveChartWidget(QWidget):
    """Interactive charts using PyQt6 Charts with Plotly integration"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup interactive chart interface"""
        layout = QVBoxLayout(self)
        
        # Chart type selector
        self.chart_selector = QComboBox()
        self.chart_selector.addItems([
            "Vulnerability Severity Distribution",
            "Scan Timeline",
            "Tool Performance",
            "Network Topology",
            "Risk Heat Map",
            "Compliance Score Trends"
        ])
        self.chart_selector.currentTextChanged.connect(self.update_chart)
        layout.addWidget(self.chart_selector)
        
        # Chart view
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        layout.addWidget(self.chart_view)
        
        # Initialize with default chart
        self.update_chart("Vulnerability Severity Distribution")
    
    def update_chart(self, chart_type: str):
        """Update chart based on selection"""
        chart = QChart()
        chart.setTheme(QChart.ChartTheme.ChartThemeDark)
        chart.setTitle(chart_type)
        
        if chart_type == "Vulnerability Severity Distribution":
            self.create_donut_chart(chart)
        elif chart_type == "Scan Timeline":
            self.create_line_chart(chart)
        elif chart_type == "Tool Performance":
            self.create_bar_chart(chart)
        elif chart_type == "Network Topology":
            self.create_scatter_chart(chart)
        elif chart_type == "Risk Heat Map":
            self.create_heatmap_chart(chart)
        
        self.chart_view.setChart(chart)
    
    def create_donut_chart(self, chart):
        """Create donut chart for vulnerability distribution"""
        series = QPieSeries()
        series.append("Critical", 15)
        series.append("High", 35)
        series.append("Medium", 40)
        series.append("Low", 10)
        
        # Set colors
        slices = series.slices()
        slices[0].setBrush(QColor("#FF0000"))  # Critical - Red
        slices[1].setBrush(QColor("#FF8800"))  # High - Orange
        slices[2].setBrush(QColor("#FFDD00"))  # Medium - Yellow
        slices[3].setBrush(QColor("#00AA00"))  # Low - Green
        
        # Make it a donut
        series.setHoleSize(0.35)
        
        # Add animations
        for slice in slices:
            slice.setExploded(False)
            slice.hovered.connect(lambda state, s=slice: s.setExploded(state))
        
        chart.addSeries(series)
    
    def create_line_chart(self, chart):
        """Create line chart for scan timeline"""
        series = QLineSeries()
        
        # Sample data
        for i in range(30):
            series.append(i, 10 + 5 * math.sin(i * 0.5) + 2 * math.random())
        
        chart.addSeries(series)
        chart.createDefaultAxes()
        
        # Customize axes
        axis_x = chart.axes(Qt.Orientation.Horizontal)[0]
        axis_y = chart.axes(Qt.Orientation.Vertical)[0]
        axis_x.setTitleText("Days")
        axis_y.setTitleText("Vulnerabilities Found")
    
    def create_bar_chart(self, chart):
        """Create bar chart for tool performance"""
        series = QBarSeries()
        
        set0 = QBarSet("Scan Speed")
        set1 = QBarSet("Accuracy")
        
        set0.append([85, 92, 78, 88, 95])
        set1.append([90, 85, 95, 82, 88])
        
        series.append(set0)
        series.append(set1)
        
        chart.addSeries(series)
        chart.createDefaultAxes()
        
        # Categories
        categories = ["Nmap", "Nuclei", "SQLMap", "Nikto", "Burp"]
        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        chart.setAxisX(axis_x, series)
    
    def create_scatter_chart(self, chart):
        """Create scatter chart for network topology"""
        series = QScatterSeries()
        series.setName("Network Nodes")
        
        # Sample network nodes
        for i in range(50):
            x = 100 * math.random()
            y = 100 * math.random()
            series.append(x, y)
        
        chart.addSeries(series)
        chart.createDefaultAxes()
    
    def create_heatmap_chart(self, chart):
        """Create heatmap using color-coded scatter plot"""
        series = QScatterSeries()
        series.setName("Risk Heat Map")
        series.setMarkerSize(15)
        
        # Sample risk data
        for i in range(20):
            for j in range(20):
                risk_level = math.sin(i * 0.3) * math.cos(j * 0.3) + 1
                series.append(i, j)
        
        chart.addSeries(series)
        chart.createDefaultAxes()

class ModernSecurityScanner(QMainWindow):
    """Main application window with modern Material Design interface"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Scanner Pro - Material Design 3")
        self.setGeometry(100, 100, 1600, 1000)
        
        # Apply modern styling
        self.apply_material_theme()
        
        # Setup UI components
        self.setup_ui()
        
        # Initialize animations
        self.setup_animations()
    
    def apply_material_theme(self):
        """Apply Material Design 3 theme"""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {MaterialColors.SURFACE};
                color: {MaterialColors.ON_SURFACE};
            }}
            
            QTabWidget::pane {{
                border: none;
                background-color: {MaterialColors.SURFACE};
            }}
            
            QTabWidget::tab-bar {{
                alignment: center;
            }}
            
            QTabBar::tab {{
                background-color: {MaterialColors.SURFACE_VARIANT};
                color: {MaterialColors.ON_SURFACE_VARIANT};
                border: none;
                padding: 12px 24px;
                margin-right: 2px;
                border-radius: 16px;
                font-weight: bold;
            }}
            
            QTabBar::tab:selected {{
                background-color: {MaterialColors.PRIMARY_CONTAINER};
                color: {MaterialColors.PRIMARY};
            }}
            
            QTabBar::tab:hover {{
                background-color: {MaterialColors.SECONDARY_CONTAINER};
            }}
        """)
    
    def setup_ui(self):
        """Setup main UI components"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Top app bar
        self.create_app_bar(main_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_analysis_tab()
        self.create_3d_visualization_tab()
        self.create_reports_tab()
        self.create_settings_tab()
    
    def create_app_bar(self, layout):
        """Create Material Design app bar"""
        app_bar = QFrame()
        app_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {MaterialColors.PRIMARY};
                color: {MaterialColors.ON_PRIMARY};
                border: none;
                padding: 16px;
                border-radius: 0 0 16px 16px;
            }}
        """)
        
        app_bar_layout = QHBoxLayout(app_bar)
        
        # Title
        title = QLabel("Security Scanner Pro")
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
            }
        """)
        app_bar_layout.addWidget(title)
        
        app_bar_layout.addStretch()
        
        # Action buttons
        sync_btn = MaterialButton("⟲ Sync", "outlined")
        settings_btn = MaterialButton("⚙ Settings", "outlined")
        
        app_bar_layout.addWidget(sync_btn)
        app_bar_layout.addWidget(settings_btn)
        
        layout.addWidget(app_bar)
    
    def create_dashboard_tab(self):
        """Create modern dashboard with cards and charts"""
        dashboard = QScrollArea()
        content = QWidget()
        layout = QVBoxLayout(content)
        
        # Stats cards row
        stats_layout = QHBoxLayout()
        
        # Vulnerability count card
        vuln_card = ModernCard("Vulnerabilities Found")
        vuln_label = QLabel("1,247")
        vuln_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #FF0000;")
        vuln_card.content_area.addWidget(vuln_label)
        stats_layout.addWidget(vuln_card)
        
        # Scan progress card
        progress_card = ModernCard("Scan Progress")
        progress_bar = QProgressBar()
        progress_bar.setValue(78)
        progress_bar.setStyleSheet(f"""
            QProgressBar {{
                border: none;
                border-radius: 8px;
                background-color: {MaterialColors.SURFACE_VARIANT};
                text-align: center;
                font-weight: bold;
            }}
            QProgressBar::chunk {{
                background-color: {MaterialColors.PRIMARY};
                border-radius: 8px;
            }}
        """)
        progress_card.content_area.addWidget(progress_bar)
        stats_layout.addWidget(progress_card)
        
        # Active scans card
        active_card = ModernCard("Active Scans")
        active_label = QLabel("23")
        active_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #00AA00;")
        active_card.content_area.addWidget(active_label)
        stats_layout.addWidget(active_card)
        
        layout.addLayout(stats_layout)
        
        # Interactive charts
        charts_card = ModernCard("Security Analytics")
        chart_widget = InteractiveChartWidget()
        charts_card.content_area.addWidget(chart_widget)
        layout.addWidget(charts_card)
        
        dashboard.setWidget(content)
        self.tab_widget.addTab(dashboard, "🏠 Dashboard")
    
    def create_scan_tab(self):
        """Create advanced scan configuration interface"""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        # Scan configuration card
        config_card = ModernCard("Scan Configuration")
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        target_input = QLineEdit()
        target_input.setPlaceholderText("Enter target URL or IP address")
        target_input.setStyleSheet(f"""
            QLineEdit {{
                border: 2px solid {MaterialColors.OUTLINE};
                border-radius: 12px;
                padding: 12px;
                font-size: 14px;
                background-color: {MaterialColors.SURFACE};
            }}
            QLineEdit:focus {{
                border-color: {MaterialColors.PRIMARY};
            }}
        """)
        target_layout.addWidget(target_input)
        config_card.content_area.addLayout(target_layout)
        
        # Tool selection with modern chips
        tools_label = QLabel("Select Tools:")
        config_card.content_area.addWidget(tools_label)
        
        tools_flow = QHBoxLayout()
        tools = ["Nmap", "Nuclei", "SQLMap", "Nikto", "Burp", "ZAP", "Wapiti", "Gobuster"]
        for tool in tools:
            chip = MaterialButton(tool, "outlined")
            chip.setCheckable(True)
            chip.setMaximumWidth(100)
            tools_flow.addWidget(chip)
        
        config_card.content_area.addLayout(tools_flow)
        
        # Start scan button
        start_btn = MaterialButton("🚀 Start Advanced Scan", "filled")
        start_btn.setStyleSheet(start_btn.styleSheet() + "font-size: 16px; padding: 16px 32px;")
        config_card.content_area.addWidget(start_btn)
        
        layout.addWidget(config_card)
        
        # Real-time results
        results_card = ModernCard("Live Scan Results")
        results_text = QTextEdit()
        results_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #1E1E1E;
                color: #00FF00;
                font-family: 'Courier New', monospace;
                border: none;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        results_text.append("Scan initialized...")
        results_text.append("Loading 500+ security tools...")
        results_text.append("Target: example.com")
        results_text.append("Status: Ready to scan")
        results_card.content_area.addWidget(results_text)
        
        layout.addWidget(results_card)
        
        self.tab_widget.addTab(scan_widget, "🔍 Scan")
    
    def create_analysis_tab(self):
        """Create vulnerability analysis interface"""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)
        
        # AI-powered analysis card
        ai_card = ModernCard("🤖 AI-Powered Vulnerability Analysis")
        
        # Risk score display
        risk_layout = QHBoxLayout()
        risk_score = QLabel("Risk Score: 8.7/10")
        risk_score.setStyleSheet("font-size: 24px; font-weight: bold; color: #FF4444;")
        risk_layout.addWidget(risk_score)
        
        risk_layout.addStretch()
        
        refresh_btn = MaterialButton("🔄 Re-analyze", "outlined")
        risk_layout.addWidget(refresh_btn)
        
        ai_card.content_area.addLayout(risk_layout)
        
        # Vulnerability list with severity indicators
        vuln_list = QListWidget()
        vuln_list.setStyleSheet(f"""
            QListWidget {{
                border: none;
                background-color: {MaterialColors.SURFACE_VARIANT};
                border-radius: 12px;
                padding: 8px;
            }}
            QListWidget::item {{
                padding: 12px;
                margin: 2px;
                border-radius: 8px;
                background-color: {MaterialColors.SURFACE};
            }}
            QListWidget::item:selected {{
                background-color: {MaterialColors.PRIMARY_CONTAINER};
            }}
        """)
        
        # Add sample vulnerabilities
        vulnerabilities = [
            ("🔴 SQL Injection in login.php", "Critical"),
            ("🟠 Cross-Site Scripting in search", "High"),
            ("🟡 Weak SSL Configuration", "Medium"),
            ("🟢 Information Disclosure", "Low")
        ]
        
        for vuln, severity in vulnerabilities:
            item = QListWidgetItem(f"{vuln} [{severity}]")
            vuln_list.addItem(item)
        
        ai_card.content_area.addWidget(vuln_list)
        layout.addWidget(ai_card)
        
        self.tab_widget.addTab(analysis_widget, "📊 Analysis")
    
    def create_3d_visualization_tab(self):
        """Create 3D visualization interface"""
        viz_widget = QWidget()
        layout = QVBoxLayout(viz_widget)
        
        # 3D Dashboard
        dashboard_3d = Dashboard3D()
        
        # Sample vulnerability data for 3D visualization
        sample_data = [
            {"name": "SQL Injection", "severity": "critical", "type": "web"},
            {"name": "XSS", "severity": "high", "type": "web"},
            {"name": "Open Port", "severity": "medium", "type": "network"},
            {"name": "Weak Password", "severity": "low", "type": "auth"}
        ]
        dashboard_3d.set_vulnerabilities_data(sample_data)
        
        layout.addWidget(dashboard_3d)
        
        # Controls
        controls_layout = QHBoxLayout()
        
        rotate_btn = MaterialButton("🔄 Auto Rotate", "outlined")
        reset_btn = MaterialButton("🏠 Reset View", "outlined")
        export_btn = MaterialButton("💾 Export 3D", "filled")
        
        controls_layout.addWidget(rotate_btn)
        controls_layout.addWidget(reset_btn)
        controls_layout.addWidget(export_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(viz_widget, "🎯 3D Visualization")
    
    def create_reports_tab(self):
        """Create modern reports interface"""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)
        
        # Report generation card
        report_card = ModernCard("📋 Advanced Report Generation")
        
        # Report type selection
        report_types = QHBoxLayout()
        for report_type in ["Executive Summary", "Technical Details", "Compliance", "Custom"]:
            btn = MaterialButton(report_type, "outlined")
            btn.setCheckable(True)
            report_types.addWidget(btn)
        
        report_card.content_area.addLayout(report_types)
        
        # Export formats
        formats_layout = QHBoxLayout()
        formats_layout.addWidget(QLabel("Export Formats:"))
        
        for format_type in ["PDF", "HTML", "JSON", "CSV", "XML"]:
            checkbox = QCheckBox(format_type)
            checkbox.setStyleSheet(f"""
                QCheckBox {{
                    font-weight: bold;
                    color: {MaterialColors.ON_SURFACE};
                }}
                QCheckBox::indicator:checked {{
                    background-color: {MaterialColors.PRIMARY};
                }}
            """)
            formats_layout.addWidget(checkbox)
        
        report_card.content_area.addLayout(formats_layout)
        
        # Generate button
        generate_btn = MaterialButton("📄 Generate Reports", "filled")
        generate_btn.setStyleSheet(generate_btn.styleSheet() + "font-size: 16px; padding: 16px 32px;")
        report_card.content_area.addWidget(generate_btn)
        
        layout.addWidget(report_card)
        
        # Report preview
        preview_card = ModernCard("📖 Report Preview")
        preview_text = QTextEdit()
        preview_text.setHtml("""
        <h2>Security Assessment Report</h2>
        <h3>Executive Summary</h3>
        <p>This comprehensive security assessment identified <b>247 vulnerabilities</b> across your infrastructure.</p>
        
        <h3>Risk Distribution</h3>
        <ul>
            <li><span style="color: red;">Critical:</span> 15 issues</li>
            <li><span style="color: orange;">High:</span> 35 issues</li>
            <li><span style="color: gold;">Medium:</span> 127 issues</li>
            <li><span style="color: green;">Low:</span> 70 issues</li>
        </ul>
        
        <h3>Top Recommendations</h3>
        <ol>
            <li>Patch critical SQL injection vulnerabilities immediately</li>
            <li>Implement proper input validation</li>
            <li>Update SSL/TLS configurations</li>
        </ol>
        """)
        
        preview_card.content_area.addWidget(preview_text)
        layout.addWidget(preview_card)
        
        self.tab_widget.addTab(reports_widget, "📊 Reports")
    
    def create_settings_tab(self):
        """Create modern settings interface"""
        settings_widget = QScrollArea()
        content = QWidget()
        layout = QVBoxLayout(content)
        
        # Theme settings
        theme_card = ModernCard("🎨 Appearance")
        
        # Dark/Light mode toggle
        theme_layout = QHBoxLayout()
        theme_layout.addWidget(QLabel("Theme:"))
        
        theme_toggle = QComboBox()
        theme_toggle.addItems(["Dark Mode", "Light Mode", "System Default"])
        theme_toggle.setStyleSheet(f"""
            QComboBox {{
                border: 2px solid {MaterialColors.OUTLINE};
                border-radius: 8px;
                padding: 8px;
                background-color: {MaterialColors.SURFACE};
            }}
        """)
        theme_layout.addWidget(theme_toggle)
        theme_layout.addStretch()
        
        theme_card.content_area.addLayout(theme_layout)
        
        # Animation settings
        anim_layout = QHBoxLayout()
        anim_layout.addWidget(QLabel("Enable Animations:"))
        
        anim_switch = QCheckBox()
        anim_switch.setChecked(True)
        anim_layout.addWidget(anim_switch)
        anim_layout.addStretch()
        
        theme_card.content_area.addLayout(anim_layout)
        
        layout.addWidget(theme_card)
        
        # Tool configuration
        tools_card = ModernCard("🔧 Tool Configuration")
        
        # Path configurations for security tools
        paths_text = QTextEdit()
        paths_text.setPlainText("""
# Tool Paths Configuration
nmap_path: /usr/bin/nmap
nuclei_path: /usr/bin/nuclei
sqlmap_path: /usr/bin/sqlmap
nikto_path: /usr/bin/nikto
gobuster_path: /usr/bin/gobuster

# Advanced Settings
max_concurrent_scans: 10
scan_timeout: 3600
enable_ai_analysis: true
auto_update_templates: true
        """)
        paths_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: #1E1E1E;
                color: #E0E0E0;
                font-family: 'Courier New', monospace;
                border: none;
                border-radius: 8px;
                padding: 12px;
            }}
        """)
        
        tools_card.content_area.addWidget(paths_text)
        
        # Save button
        save_btn = MaterialButton("💾 Save Configuration", "filled")
        tools_card.content_area.addWidget(save_btn)
        
        layout.addWidget(tools_card)
        
        settings_widget.setWidget(content)
        self.tab_widget.addTab(settings_widget, "⚙ Settings")
    
    def setup_animations(self):
        """Setup window animations"""
        # Fade in animation on startup
        self.fade_animation = MaterialAnimations.create_fade_in(self, 500)
        self.fade_animation.start()

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Security Scanner Pro")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("Security Solutions Inc.")
    
    # Apply global style
    app.setStyle("Fusion")
    
    # Create and show main window
    window = ModernSecurityScanner()
    window.show()
    
    return app.exec()

if __name__ == "__main__":
    sys.exit(main())