"""
Fixed Modern Material Design GUI Interface
Advanced PyQt implementation with proper error handling and fallbacks
"""

import sys
import os
import json
import math
from datetime import datetime
from typing import Dict, List, Any, Optional
import threading

# GUI Framework imports with fallbacks
try:
    from PyQt6.QtWidgets import *
    from PyQt6.QtCore import *
    from PyQt6.QtGui import *
    PYQT6_AVAILABLE = True
    QT_VERSION = 6
except ImportError:
    try:
        from PyQt5.QtWidgets import *
        from PyQt5.QtCore import *
        from PyQt5.QtGui import *
        PYQT6_AVAILABLE = False
        QT_VERSION = 5
    except ImportError:
        print("Error: No Qt installation found. Please install PyQt5 or PyQt6")
        sys.exit(1)

# Optional imports with fallbacks
try:
    if PYQT6_AVAILABLE:
        from PyQt6.QtOpenGL import QOpenGLWidget
        from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    else:
        from PyQt5.QtOpenGL import QOpenGLWidget
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

# Scientific computing imports
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.offline import plot
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

try:
    import dash
    from dash import html, dcc, Input, Output
    DASH_AVAILABLE = True
except ImportError:
    DASH_AVAILABLE = False

# Import core modules
from core.config_manager import ConfigManager
from core.logger import get_security_logger

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
        if QT_VERSION == 6:
            self.setEasingCurve(QEasingCurve.Type.OutCubic)
        else:
            self.setEasingCurve(QEasingCurve.OutCubic)
    
    @staticmethod
    def create_fade_in(widget: QWidget, duration: int = 300) -> QPropertyAnimation:
        """Create fade in animation"""
        animation = MaterialAnimations(widget, "windowOpacity", duration)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
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
        if QT_VERSION == 6:
            self.setFrameShape(QFrame.Shape.Box)
        else:
            self.setFrameShape(QFrame.Box)
            
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {MaterialColors.SURFACE};
                border: none;
                border-radius: 16px;
                padding: 16px;
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
        if QT_VERSION == 6:
            enter_event = QEvent.Type.Enter
            leave_event = QEvent.Type.Leave
        else:
            enter_event = QEvent.Enter
            leave_event = QEvent.Leave
            
        if event.type() == enter_event:
            self.animate_hover_in()
        elif event.type() == leave_event:
            self.animate_hover_out()
        return super().eventFilter(obj, event)
    
    def animate_hover_in(self):
        """Animate card on hover"""
        try:
            self.hover_animation = MaterialAnimations.create_scale_animation(self, 1.02, 200)
            self.hover_animation.start()
        except:
            pass  # Ignore animation errors
    
    def animate_hover_out(self):
        """Animate card on leave"""
        try:
            self.hover_animation = MaterialAnimations.create_scale_animation(self, 1.0, 200)
            self.hover_animation.start()
        except:
            pass  # Ignore animation errors

class MaterialButton(QPushButton):
    """Material Design Button with animations"""
    
    def __init__(self, text: str = "", button_type: str = "filled", parent=None):
        super().__init__(text, parent)
        self.button_type = button_type
        self.setup_ui()
    
    def setup_ui(self):
        """Setup button with Material Design styling"""
        if QT_VERSION == 6:
            self.setCursor(Qt.CursorShape.PointingHandCursor)
        else:
            self.setCursor(Qt.PointingHandCursor)
            
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

class Dashboard3DWidget(QWidget):
    """3D/2D Visualization Dashboard with fallback"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.vulnerabilities_data = []
        self.setup_ui()
    
    def setup_ui(self):
        """Setup dashboard UI"""
        layout = QVBoxLayout(self)
        
        if OPENGL_AVAILABLE:
            # Try to create OpenGL widget
            try:
                self.gl_widget = self.create_opengl_widget()
                layout.addWidget(self.gl_widget)
            except Exception as e:
                print(f"OpenGL initialization failed: {e}")
                self.create_fallback_widget(layout)
        else:
            self.create_fallback_widget(layout)
    
    def create_opengl_widget(self):
        """Create OpenGL 3D widget"""
        if OPENGL_AVAILABLE:
            return OpenGL3DWidget()
        return None
    
    def create_fallback_widget(self, layout):
        """Create fallback 2D widget"""
        label = QLabel("3D Visualization\n(Using 2D fallback)")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("""
            QLabel {
                color: #666;
                font-size: 14px;
                border: 2px dashed #ccc;
                border-radius: 8px;
                padding: 40px;
                background-color: #f9f9f9;
            }
        """)
        layout.addWidget(label)
        
        # Add simple vulnerability list
        self.vuln_list = QListWidget()
        self.vuln_list.setStyleSheet("""
            QListWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: white;
            }
        """)
        layout.addWidget(self.vuln_list)
    
    def set_vulnerabilities_data(self, data: List[Dict[str, Any]]):
        """Update vulnerability data"""
        self.vulnerabilities_data = data
        
        # Update fallback list if it exists
        if hasattr(self, 'vuln_list'):
            self.vuln_list.clear()
            for vuln in data[:10]:  # Show top 10
                item_text = f"{vuln.get('name', 'Unknown')} [{vuln.get('severity', 'low')}]"
                self.vuln_list.addItem(item_text)

if OPENGL_AVAILABLE:
    class OpenGL3DWidget(QOpenGLWidget):
        """OpenGL 3D visualization widget"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.vulnerabilities_data = []
            self.rotation_y = 0
            
            # Animation timer
            self.timer = QTimer()
            self.timer.timeout.connect(self.update_rotation)
            self.timer.start(50)
        
        def initializeGL(self):
            """Initialize OpenGL"""
            try:
                import OpenGL.GL as gl
                gl.glEnable(gl.GL_DEPTH_TEST)
                gl.glClearColor(0.1, 0.1, 0.1, 1.0)
            except ImportError:
                print("PyOpenGL not available")
        
        def resizeGL(self, width, height):
            """Handle resize"""
            try:
                import OpenGL.GL as gl
                import OpenGL.GLU as glu
                gl.glViewport(0, 0, width, height)
                gl.glMatrixMode(gl.GL_PROJECTION)
                gl.glLoadIdentity()
                glu.gluPerspective(45, width/height if height != 0 else 1, 1, 100)
                gl.glMatrixMode(gl.GL_MODELVIEW)
            except ImportError:
                pass
        
        def paintGL(self):
            """Paint OpenGL scene"""
            try:
                import OpenGL.GL as gl
                import OpenGL.GLU as glu
                
                gl.glClear(gl.GL_COLOR_BUFFER_BIT | gl.GL_DEPTH_BUFFER_BIT)
                gl.glLoadIdentity()
                gl.glTranslatef(0, 0, -5)
                gl.glRotatef(self.rotation_y, 0, 1, 0)
                
                # Draw simple cube as placeholder
                self.draw_cube()
                
            except ImportError:
                pass
        
        def draw_cube(self):
            """Draw a simple cube"""
            try:
                import OpenGL.GL as gl
                
                gl.glBegin(gl.GL_QUADS)
                # Front face
                gl.glColor3f(1.0, 0.0, 0.0)
                gl.glVertex3f(-1, -1, 1)
                gl.glVertex3f(1, -1, 1)
                gl.glVertex3f(1, 1, 1)
                gl.glVertex3f(-1, 1, 1)
                gl.glEnd()
                
            except ImportError:
                pass
        
        def update_rotation(self):
            """Update rotation"""
            self.rotation_y += 1
            if self.rotation_y >= 360:
                self.rotation_y = 0
            self.update()
else:
    class OpenGL3DWidget(QWidget):
        """Fallback 3D widget when OpenGL is not available"""
        
        def __init__(self, parent=None):
            super().__init__(parent)
            self.vulnerabilities_data = []
            self.setup_fallback_ui()
        
        def setup_fallback_ui(self):
            """Setup fallback UI"""
            layout = QVBoxLayout(self)
            label = QLabel("3D Visualization not available")
            label.setAlignment(Qt.AlignCenter)
            layout.addWidget(label)
        
        def set_vulnerabilities_data(self, data: List[Dict[str, Any]]):
            """Update vulnerability data"""
            self.vulnerabilities_data = data

class InteractiveChartWidget(QWidget):
    """Interactive charts with fallback support"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
    
    def setup_ui(self):
        """Setup chart interface"""
        layout = QVBoxLayout(self)
        
        # Chart type selector
        self.chart_selector = QComboBox()
        self.chart_selector.addItems([
            "Vulnerability Severity Distribution",
            "Scan Timeline",
            "Tool Performance",
            "Network Topology",
            "Risk Heat Map"
        ])
        self.chart_selector.currentTextChanged.connect(self.update_chart)
        layout.addWidget(self.chart_selector)
        
        if CHARTS_AVAILABLE:
            # Use Qt Charts
            self.setup_qt_charts(layout)
        else:
            # Use fallback
            self.setup_fallback_charts(layout)
        
        # Initialize with default chart
        self.update_chart("Vulnerability Severity Distribution")
    
    def setup_qt_charts(self, layout):
        """Setup Qt Charts"""
        self.chart_view = QChartView()
        if QT_VERSION == 6:
            self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        else:
            self.chart_view.setRenderHint(QPainter.Antialiasing)
        layout.addWidget(self.chart_view)
    
    def setup_fallback_charts(self, layout):
        """Setup fallback charts"""
        self.chart_label = QLabel("Chart Visualization")
        self.chart_label.setAlignment(Qt.AlignCenter)
        self.chart_label.setStyleSheet("""
            QLabel {
                border: 2px solid #ddd;
                border-radius: 8px;
                padding: 20px;
                background-color: #f5f5f5;
                min-height: 300px;
            }
        """)
        layout.addWidget(self.chart_label)
        
        # Simple data display
        self.data_text = QTextEdit()
        self.data_text.setMaximumHeight(150)
        self.data_text.setReadOnly(True)
        layout.addWidget(self.data_text)
    
    def update_chart(self, chart_type: str):
        """Update chart based on selection"""
        if CHARTS_AVAILABLE:
            self.update_qt_chart(chart_type)
        else:
            self.update_fallback_chart(chart_type)
    
    def update_qt_chart(self, chart_type: str):
        """Update Qt chart"""
        try:
            chart = QChart()
            if QT_VERSION == 6:
                chart.setTheme(QChart.ChartTheme.ChartThemeDark)
            else:
                chart.setTheme(QChart.ChartThemeDark)
            chart.setTitle(chart_type)
            
            if chart_type == "Vulnerability Severity Distribution":
                self.create_pie_chart(chart)
            elif chart_type == "Tool Performance":
                self.create_bar_chart(chart)
            else:
                self.create_line_chart(chart)
            
            self.chart_view.setChart(chart)
        except Exception as e:
            print(f"Chart update error: {e}")
    
    def update_fallback_chart(self, chart_type: str):
        """Update fallback chart"""
        self.chart_label.setText(f"Chart: {chart_type}\n(Charts library not available)")
        
        # Show sample data
        if chart_type == "Vulnerability Severity Distribution":
            data = "Critical: 15\nHigh: 35\nMedium: 127\nLow: 70"
        elif chart_type == "Tool Performance":
            data = "Nmap: 45 findings\nNuclei: 89 findings\nNikto: 23 findings"
        else:
            data = "Sample timeline data would be displayed here"
        
        if hasattr(self, 'data_text'):
            self.data_text.setText(data)
    
    def create_pie_chart(self, chart):
        """Create pie chart"""
        if CHARTS_AVAILABLE:
            series = QPieSeries()
            series.append("Critical", 15)
            series.append("High", 35)
            series.append("Medium", 127)
            series.append("Low", 70)
            chart.addSeries(series)
    
    def create_bar_chart(self, chart):
        """Create bar chart"""
        if CHARTS_AVAILABLE:
            series = QBarSeries()
            bar_set = QBarSet("Findings")
            bar_set.append([45, 89, 23, 67, 34])
            series.append(bar_set)
            chart.addSeries(series)
    
    def create_line_chart(self, chart):
        """Create line chart"""
        if CHARTS_AVAILABLE:
            series = QLineSeries()
            for i in range(10):
                series.append(i, i * 2 + 5)
            chart.addSeries(series)

class ModernSecurityScanner(QMainWindow):
    """Main application window with modern design"""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Scanner Pro - Modern Interface")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply theme
        self.apply_material_theme()
        
        # Setup UI
        self.setup_ui()
        
        # Initialize animations
        self.setup_animations()
    
    def apply_material_theme(self):
        """Apply Material Design theme"""
        self.setStyleSheet(f"""
            QMainWindow {{
                background-color: {MaterialColors.SURFACE};
                color: {MaterialColors.ON_SURFACE};
            }}
            
            QTabWidget::pane {{
                border: none;
                background-color: {MaterialColors.SURFACE};
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
        """Setup main UI"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout(central_widget)
        
        # Create app bar
        self.create_app_bar(main_layout)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_scan_tab()
        self.create_analysis_tab()
        self.create_3d_tab()
        self.create_reports_tab()
        self.create_settings_tab()
    
    def create_app_bar(self, layout):
        """Create app bar"""
        app_bar = QFrame()
        app_bar.setStyleSheet(f"""
            QFrame {{
                background-color: {MaterialColors.PRIMARY};
                color: {MaterialColors.ON_PRIMARY};
                border: none;
                padding: 16px;
            }}
        """)
        
        app_bar_layout = QHBoxLayout(app_bar)
        
        title = QLabel("Security Scanner Pro")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        app_bar_layout.addWidget(title)
        
        app_bar_layout.addStretch()
        
        sync_btn = MaterialButton("⟲ Sync", "outlined")
        sync_btn.setStyleSheet("color: white; border-color: white;")
        app_bar_layout.addWidget(sync_btn)
        
        layout.addWidget(app_bar)
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard = QScrollArea()
        content = QWidget()
        layout = QVBoxLayout(content)
        
        # Stats cards
        stats_layout = QHBoxLayout()
        
        vuln_card = ModernCard("Vulnerabilities Found")
        vuln_label = QLabel("247")
        vuln_label.setStyleSheet("font-size: 36px; font-weight: bold; color: #FF0000;")
        vuln_card.content_area.addWidget(vuln_label)
        stats_layout.addWidget(vuln_card)
        
        progress_card = ModernCard("Scan Progress")
        progress_bar = QProgressBar()
        progress_bar.setValue(75)
        progress_card.content_area.addWidget(progress_bar)
        stats_layout.addWidget(progress_card)
        
        layout.addLayout(stats_layout)
        
        # Interactive charts
        charts_card = ModernCard("Security Analytics")
        chart_widget = InteractiveChartWidget()
        charts_card.content_area.addWidget(chart_widget)
        layout.addWidget(charts_card)
        
        dashboard.setWidget(content)
        self.tab_widget.addTab(dashboard, "🏠 Dashboard")
    
    def create_scan_tab(self):
        """Create scan tab"""
        scan_widget = QWidget()
        layout = QVBoxLayout(scan_widget)
        
        config_card = ModernCard("Scan Configuration")
        
        # Target input
        target_layout = QHBoxLayout()
        target_layout.addWidget(QLabel("Target:"))
        target_input = QLineEdit()
        target_input.setPlaceholderText("Enter target URL or IP")
        target_layout.addWidget(target_input)
        config_card.content_area.addLayout(target_layout)
        
        # Tool selection
        tools_layout = QHBoxLayout()
        for tool in ["Nmap", "Nuclei", "SQLMap", "Nikto"]:
            btn = MaterialButton(tool, "outlined")
            btn.setCheckable(True)
            tools_layout.addWidget(btn)
        config_card.content_area.addLayout(tools_layout)
        
        # Start button
        start_btn = MaterialButton("🚀 Start Scan", "filled")
        config_card.content_area.addWidget(start_btn)
        
        layout.addWidget(config_card)
        
        # Results area
        results_card = ModernCard("Live Results")
        results_text = QTextEdit()
        results_text.setStyleSheet("""
            QTextEdit {
                background-color: #1E1E1E;
                color: #00FF00;
                font-family: 'Courier New', monospace;
                border: none;
                border-radius: 8px;
            }
        """)
        results_text.setText("Scan initialized...\nReady to start scanning...")
        results_card.content_area.addWidget(results_text)
        
        layout.addWidget(results_card)
        
        self.tab_widget.addTab(scan_widget, "🔍 Scan")
    
    def create_analysis_tab(self):
        """Create analysis tab"""
        analysis_widget = QWidget()
        layout = QVBoxLayout(analysis_widget)
        
        ai_card = ModernCard("🤖 AI Analysis")
        ai_card.content_area.addWidget(QLabel("AI-powered vulnerability analysis would appear here"))
        layout.addWidget(ai_card)
        
        self.tab_widget.addTab(analysis_widget, "📊 Analysis")
    
    def create_3d_tab(self):
        """Create 3D visualization tab"""
        viz_widget = QWidget()
        layout = QVBoxLayout(viz_widget)
        
        dashboard_3d = Dashboard3DWidget()
        layout.addWidget(dashboard_3d)
        
        # Controls
        controls_layout = QHBoxLayout()
        rotate_btn = MaterialButton("🔄 Rotate", "outlined")
        reset_btn = MaterialButton("🏠 Reset", "outlined")
        controls_layout.addWidget(rotate_btn)
        controls_layout.addWidget(reset_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        self.tab_widget.addTab(viz_widget, "🎯 3D View")
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports_widget = QWidget()
        layout = QVBoxLayout(reports_widget)
        
        report_card = ModernCard("📋 Report Generation")
        report_card.content_area.addWidget(QLabel("Report generation options would appear here"))
        layout.addWidget(report_card)
        
        self.tab_widget.addTab(reports_widget, "📊 Reports")
    
    def create_settings_tab(self):
        """Create settings tab"""
        settings_widget = QWidget()
        layout = QVBoxLayout(settings_widget)
        
        settings_card = ModernCard("⚙ Settings")
        settings_card.content_area.addWidget(QLabel("Application settings would appear here"))
        layout.addWidget(settings_card)
        
        self.tab_widget.addTab(settings_widget, "⚙ Settings")
    
    def setup_animations(self):
        """Setup animations"""
        try:
            self.fade_animation = MaterialAnimations.create_fade_in(self, 500)
            self.fade_animation.start()
        except:
            pass  # Ignore animation errors

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("Security Scanner Pro")
    app.setApplicationVersion("2.0.0")
    app.setOrganizationName("Security Solutions")
    
    # Apply fusion style for better look
    app.setStyle("Fusion")
    
    # Create and show main window
    window = ModernSecurityScanner()
    window.show()
    
    return app.exec() if QT_VERSION == 6 else app.exec_()

if __name__ == "__main__":
    sys.exit(main())