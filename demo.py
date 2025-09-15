#!/usr/bin/env python3
"""
Security Scanner Demo
Demonstrates the working functionality of the enhanced security scanner
"""

import sys
import os
import asyncio
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

async def demo_core_functionality():
    """Demo core functionality without GUI"""
    
    print("🔐 ADVANCED SECURITY SCANNER DEMO")
    print("=" * 50)
    
    # 1. Configuration Management
    print("\n1. Configuration Management")
    from core.config_manager import ConfigManager
    
    config = ConfigManager()
    print(f"✓ Configuration loaded")
    print(f"  - Tools enabled: {len([t for t, c in config.get_all_tools().items() if c.get('enabled', False)])}")
    print(f"  - Profiles available: {len(config.get_all_profiles())}")
    
    # 2. Logging System
    print("\n2. Security Logging")
    from core.logger import get_security_logger
    
    logger = get_security_logger("demo")
    logger.info("Demo logging system initialized")
    logger.log_scan_start("example.com", "demo", "quick_scan")
    logger.log_vulnerability_found("example.com", "Demo Vulnerability", "medium", "For demonstration only")
    print("✓ Security logging operational")
    
    # 3. Plugin System with AI Analysis
    print("\n3. AI-Powered Plugin System")
    from plugins.plugin_manager_fixed import PluginManager
    
    plugin_manager = PluginManager(config)
    print(f"✓ Plugin manager initialized")
    print(f"  - Available plugins: {len(plugin_manager.get_available_plugins())}")
    
    # Demo vulnerability analysis
    sample_vulnerabilities = [
        {
            'type': 'SQL Injection',
            'severity': 'critical',
            'target': 'demo.example.com',
            'description': 'SQL injection in login form',
            'cvss_score': 9.8,
            'cve': 'CVE-2024-DEMO1',
            'service': 'http',
            'tool': 'sqlmap'
        },
        {
            'type': 'Cross-Site Scripting',
            'severity': 'high', 
            'target': 'demo.example.com',
            'description': 'Reflected XSS in search parameter',
            'cvss_score': 7.2,
            'service': 'http',
            'tool': 'nuclei'
        },
        {
            'type': 'Information Disclosure',
            'severity': 'medium',
            'target': 'demo.example.com',
            'description': 'Server information leaked in headers',
            'cvss_score': 4.3,
            'service': 'http',
            'tool': 'nikto'
        }
    ]
    
    analysis = await plugin_manager.ai_analyzer.analyze_vulnerabilities(sample_vulnerabilities)
    print(f"✓ AI Analysis completed")
    print(f"  - Vulnerabilities analyzed: {analysis['total_vulnerabilities']}")
    print(f"  - Risk Score: {analysis['risk_score']:.1f}/10.0")
    print(f"  - Priority vulnerabilities: {len(analysis['priority_vulnerabilities'])}")
    print(f"  - Recommendations: {len(analysis['recommendations'])}")
    
    # 4. Report Generation
    print("\n4. Report Generation")
    from reports.report_generator import ReportGenerator
    
    report_gen = ReportGenerator(config)
    
    # Prepare sample scan data
    scan_data = {
        'scan_info': {
            'target': 'demo.example.com',
            'timestamp': '2024-09-16T00:30:00Z',
            'duration': 300,
            'tools_used': ['nuclei', 'nikto', 'sqlmap']
        },
        'vulnerabilities': sample_vulnerabilities,
        'summary': {
            'total_vulnerabilities': 3,
            'critical': 1,
            'high': 1,
            'medium': 1,
            'low': 0
        },
        'ai_analysis': analysis
    }
    
    # Generate HTML report
    html_report = report_gen.generate_html_report(scan_data, "demo_report.html")
    print(f"✓ HTML Report generated: {html_report}")
    
    # Generate JSON report
    json_report = report_gen.generate_json_report(scan_data, "demo_report.json")
    print(f"✓ JSON Report generated: {json_report}")
    
    print(f"\n📊 Report Statistics:")
    print(f"  - Total findings: {len(sample_vulnerabilities)}")
    print(f"  - Critical: {scan_data['summary']['critical']}")
    print(f"  - High: {scan_data['summary']['high']}")
    print(f"  - Medium: {scan_data['summary']['medium']}")
    
    # 5. Show Top Recommendations
    print(f"\n🎯 Top AI Recommendations:")
    for i, rec in enumerate(analysis['recommendations'][:3], 1):
        print(f"  {i}. {rec['title']} ({rec['priority']})")
        print(f"     {rec['description']}")

def demo_gui():
    """Demo GUI functionality"""
    print("\n5. Modern GUI Interface")
    
    try:
        from PyQt6.QtWidgets import QApplication
        from gui.modern_interface_fixed import ModernSecurityScanner
        
        print("✓ Modern Material Design interface available")
        print("  - Material Design 3 components")
        print("  - 3D visualizations (fallback available)")
        print("  - Interactive charts")
        print("  - Real-time dashboard")
        
        # Note: We don't actually start the GUI in demo mode
        print("  (GUI demo requires interactive mode)")
        
    except Exception as e:
        print(f"⚠ GUI demo skipped: {e}")

def show_system_capabilities():
    """Show system capabilities and features"""
    
    print("\n🚀 SYSTEM CAPABILITIES")
    print("=" * 50)
    
    capabilities = [
        ("🔧 Core Features", [
            "Multi-threaded security scanning",
            "50+ integrated security tools",
            "OWASP WSTG compliance testing", 
            "API security assessment",
            "Real-time vulnerability analysis"
        ]),
        ("🤖 AI-Powered Analysis", [
            "Machine learning vulnerability classification",
            "Risk scoring algorithms",
            "False positive detection",
            "Intelligent vulnerability prioritization",
            "Automated remediation recommendations"
        ]),
        ("📊 Advanced Reporting", [
            "Interactive HTML reports",
            "PDF executive summaries",
            "JSON data exports",
            "Real-time dashboards",
            "SIEM integration support"
        ]),
        ("🎨 Modern Interface", [
            "Material Design 3 UI",
            "3D vulnerability visualizations",
            "Interactive charts and graphs",
            "Dark/light theme support",
            "Responsive design"
        ]),
        ("🔌 Extensibility", [
            "Plugin architecture",
            "Custom tool integration",
            "REST API support",
            "WebSocket real-time updates",
            "Configuration management"
        ])
    ]
    
    for category, features in capabilities:
        print(f"\n{category}")
        for feature in features:
            print(f"  ✓ {feature}")

async def main():
    """Main demo function"""
    
    try:
        # Show system overview
        show_system_capabilities()
        
        # Demo core functionality
        await demo_core_functionality()
        
        # Demo GUI (non-interactive)
        demo_gui()
        
        print("\n" + "=" * 50)
        print("🎉 DEMO COMPLETED SUCCESSFULLY!")
        print("=" * 50)
        print("\nTo run the full application:")
        print("  python3 main.py                    # Standard GUI")
        print("  python3 src/gui/modern_interface_fixed.py  # Modern Material Design GUI")
        print("\nGenerated files:")
        print("  demo_report.html - Interactive security report")
        print("  demo_report.json - Raw scan data")
        print("\n📚 Documentation and examples available in the project directory.")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    try:
        result = asyncio.run(main())
        sys.exit(0 if result else 1)
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
        sys.exit(1)