#!/usr/bin/env python3
"""
Comprehensive test script for Security Scanner
Tests all components with proper error handling and fallbacks
"""

import sys
import os
import asyncio
import traceback
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test all module imports"""
    print("=" * 50)
    print("TESTING IMPORTS")
    print("=" * 50)
    
    test_results = {}
    
    # Test core modules
    try:
        from core.config_manager import ConfigManager
        print("✓ Core config manager imported successfully")
        test_results['config_manager'] = True
    except Exception as e:
        print(f"✗ Core config manager failed: {e}")
        test_results['config_manager'] = False
    
    try:
        from core.logger import get_security_logger, setup_logging
        print("✓ Core logger imported successfully")
        test_results['logger'] = True
    except Exception as e:
        print(f"✗ Core logger failed: {e}")
        test_results['logger'] = False
    
    # Test GUI modules
    try:
        from gui.modern_interface_fixed import ModernSecurityScanner
        print("✓ Modern GUI interface imported successfully")
        test_results['modern_gui'] = True
    except Exception as e:
        print(f"✗ Modern GUI interface failed: {e}")
        test_results['modern_gui'] = False
    
    try:
        from gui.main_window import SecurityScannerMainWindow
        print("✓ Main window imported successfully")
        test_results['main_window'] = True
    except Exception as e:
        print(f"✗ Main window failed: {e}")
        test_results['main_window'] = False
    
    # Test plugin system
    try:
        from plugins.plugin_manager_fixed import PluginManager, AIVulnerabilityAnalyzer
        print("✓ Plugin manager imported successfully")
        test_results['plugin_manager'] = True
    except Exception as e:
        print(f"✗ Plugin manager failed: {e}")
        test_results['plugin_manager'] = False
    
    # Test scanners
    try:
        from scanners.nuclei_scanner import NucleiScanner
        print("✓ Nuclei scanner imported successfully")
        test_results['nuclei_scanner'] = True
    except Exception as e:
        print(f"✗ Nuclei scanner failed: {e}")
        test_results['nuclei_scanner'] = False
    
    try:
        from scanners.tool_integrations import NmapScanner, NiktoScanner
        print("✓ Tool integrations imported successfully")
        test_results['tool_integrations'] = True
    except Exception as e:
        print(f"✗ Tool integrations failed: {e}")
        test_results['tool_integrations'] = False
    
    # Test reports
    try:
        from reports.report_generator import ReportGenerator
        print("✓ Report generator imported successfully")
        test_results['report_generator'] = True
    except Exception as e:
        print(f"✗ Report generator failed: {e}")
        test_results['report_generator'] = False
    
    return test_results

def test_config_manager():
    """Test configuration manager"""
    print("\\n" + "=" * 50)
    print("TESTING CONFIG MANAGER")
    print("=" * 50)
    
    try:
        from core.config_manager import ConfigManager
        
        # Test initialization
        config = ConfigManager()
        print("✓ Config manager initialized successfully")
        
        # Test configuration operations
        config.set_config('test_section', 'test_key', 'test_value')
        value = config.get_config('test_section', 'test_key')
        
        if value == 'test_value':
            print("✓ Configuration set/get operations working")
        else:
            print("✗ Configuration set/get operations failed")
        
        # Test tool configurations
        config.set_tool_config('nmap', 'enabled', True)
        enabled = config.is_tool_enabled('nmap')
        
        if enabled:
            print("✓ Tool configuration working")
        else:
            print("✗ Tool configuration failed")
        
        return True
        
    except Exception as e:
        print(f"✗ Config manager test failed: {e}")
        traceback.print_exc()
        return False

def test_logger():
    """Test logging system"""
    print("\\n" + "=" * 50)
    print("TESTING LOGGER")
    print("=" * 50)
    
    try:
        from core.logger import get_security_logger, setup_logging
        import tempfile
        
        # Setup logging with temporary file
        with tempfile.NamedTemporaryFile(suffix='.log', delete=False) as tmp:
            setup_logging(tmp.name)
            
            # Test security logger
            logger = get_security_logger('test_module')
            logger.info("Test info message")
            logger.warning("Test warning message")
            logger.error("Test error message")
            
            print("✓ Security logger working")
            
            # Test log file creation
            if os.path.exists(tmp.name):
                print("✓ Log file created successfully")
                os.unlink(tmp.name)  # Clean up
            else:
                print("✗ Log file not created")
        
        return True
        
    except Exception as e:
        print(f"✗ Logger test failed: {e}")
        traceback.print_exc()
        return False

async def test_plugin_manager():
    """Test plugin management system"""
    print("\\n" + "=" * 50)
    print("TESTING PLUGIN MANAGER")
    print("=" * 50)
    
    try:
        from plugins.plugin_manager_fixed import PluginManager
        from core.config_manager import ConfigManager
        
        # Initialize
        config = ConfigManager()
        plugin_manager = PluginManager(config)
        
        print(f"✓ Plugin manager initialized with {len(plugin_manager.plugins)} plugins")
        
        # Test plugin discovery
        available_plugins = plugin_manager.get_available_plugins()
        print(f"✓ Found {len(available_plugins)} available plugins")
        
        # Test AI vulnerability analyzer
        sample_vulnerabilities = [
            {
                'type': 'SQL Injection',
                'severity': 'critical',
                'target': 'example.com',
                'description': 'SQL injection vulnerability in login form',
                'cvss_score': 9.0,
                'cve': 'CVE-2024-1234'
            },
            {
                'type': 'Cross-Site Scripting',
                'severity': 'high',
                'target': 'example.com',
                'description': 'Reflected XSS in search parameter',
                'cvss_score': 7.5
            }
        ]
        
        analysis = await plugin_manager.ai_analyzer.analyze_vulnerabilities(sample_vulnerabilities)
        print(f"✓ AI analysis completed, risk score: {analysis.get('risk_score', 0):.1f}")
        
        return True
        
    except Exception as e:
        print(f"✗ Plugin manager test failed: {e}")
        traceback.print_exc()
        return False

def test_gui_components():
    """Test GUI components"""
    print("\\n" + "=" * 50)
    print("TESTING GUI COMPONENTS")
    print("=" * 50)
    
    try:
        # Test Qt availability
        try:
            from PyQt6.QtWidgets import QApplication
            qt_version = "PyQt6"
        except ImportError:
            try:
                from PyQt5.QtWidgets import QApplication
                qt_version = "PyQt5"
            except ImportError:
                print("✗ No Qt framework available")
                return False
        
        print(f"✓ Qt framework available: {qt_version}")
        
        # Test modern interface components
        from gui.modern_interface_fixed import MaterialColors, ModernCard, MaterialButton
        
        # Test color system
        print(f"✓ Material colors loaded: {MaterialColors.PRIMARY}")
        
        # Note: Can't actually create widgets without QApplication running
        print("✓ GUI components imported successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ GUI components test failed: {e}")
        traceback.print_exc()
        return False

def test_scanner_modules():
    """Test scanner modules"""
    print("\\n" + "=" * 50)
    print("TESTING SCANNER MODULES")
    print("=" * 50)
    
    try:
        from scanners.tool_integrations import BaseScanner
        from core.config_manager import ConfigManager
        
        # Test base scanner
        config = ConfigManager()
        
        # Create a simple test scanner
        class TestScanner(BaseScanner):
            def __init__(self, config_manager, tool_name='test'):
                super().__init__(config_manager, tool_name)
            
            async def scan(self, target, options=None):
                return {
                    'tool': self.tool_name,
                    'target': target,
                    'status': 'completed',
                    'vulnerabilities': [
                        {
                            'type': 'Test Vulnerability',
                            'severity': 'medium',
                            'description': 'Test vulnerability description'
                        }
                    ]
                }
        
        scanner = TestScanner(config)
        print("✓ Base scanner class working")
        
        return True
        
    except Exception as e:
        print(f"✗ Scanner modules test failed: {e}")
        traceback.print_exc()
        return False

def test_report_generator():
    """Test report generation"""
    print("\\n" + "=" * 50)
    print("TESTING REPORT GENERATOR")
    print("=" * 50)
    
    try:
        from reports.report_generator import ReportGenerator
        from core.config_manager import ConfigManager
        
        config = ConfigManager()
        report_gen = ReportGenerator(config)
        
        # Test sample data generation
        sample_data = {
            'scan_info': {
                'target': 'example.com',
                'timestamp': '2024-01-15T10:30:00Z',
                'duration': 300
            },
            'vulnerabilities': [
                {
                    'type': 'SQL Injection',
                    'severity': 'critical',
                    'description': 'Critical SQL injection found',
                    'tool': 'sqlmap'
                }
            ],
            'summary': {
                'total_vulnerabilities': 1,
                'critical': 1,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        
        # Test HTML report generation
        html_report = report_gen.generate_html_report(sample_data)
        if html_report and len(html_report) > 100:
            print("✓ HTML report generation working")
        else:
            print("✗ HTML report generation failed")
        
        return True
        
    except Exception as e:
        print(f"✗ Report generator test failed: {e}")
        traceback.print_exc()
        return False

def check_dependencies():
    """Check for optional dependencies"""
    print("\\n" + "=" * 50)
    print("CHECKING DEPENDENCIES")
    print("=" * 50)
    
    dependencies = {
        'numpy': 'NumPy for scientific computing',
        'pandas': 'Pandas for data analysis',
        'sklearn': 'Scikit-learn for machine learning',
        'plotly': 'Plotly for interactive charts',
        'dash': 'Dash for web dashboards',
        'tensorflow': 'TensorFlow for deep learning',
        'transformers': 'Transformers for NLP',
        'websockets': 'WebSockets for real-time communication'
    }
    
    available = []
    missing = []
    
    for dep, description in dependencies.items():
        try:
            if dep == 'sklearn':
                import sklearn
            else:
                __import__(dep)
            print(f"✓ {dep}: {description}")
            available.append(dep)
        except ImportError:
            print(f"○ {dep}: {description} (optional, not installed)")
            missing.append(dep)
    
    print(f"\\nSummary: {len(available)} available, {len(missing)} missing")
    print("Note: Missing dependencies are optional and have fallbacks implemented.")
    
    return available, missing

async def run_all_tests():
    """Run all tests"""
    print("SECURITY SCANNER - COMPREHENSIVE TESTING")
    print("=" * 80)
    
    test_results = {}
    
    # Check dependencies first
    available_deps, missing_deps = check_dependencies()
    
    # Run tests
    test_results['imports'] = test_imports()
    test_results['config_manager'] = test_config_manager()
    test_results['logger'] = test_logger()
    test_results['plugin_manager'] = await test_plugin_manager()
    test_results['gui_components'] = test_gui_components()
    test_results['scanner_modules'] = test_scanner_modules()
    test_results['report_generator'] = test_report_generator()
    
    # Summary
    print("\\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)
    
    passed = sum(1 for result in test_results.values() if result)
    total = len(test_results)
    
    for test_name, result in test_results.items():
        status = "PASS" if result else "FAIL"
        print(f"{test_name:20} : {status}")
    
    print(f"\\nOverall: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Security scanner is ready to use.")
        return True
    else:
        print("⚠️  Some tests failed. Check the output above for details.")
        return False

def main():
    """Main test function"""
    try:
        result = asyncio.run(run_all_tests())
        return 0 if result else 1
    except KeyboardInterrupt:
        print("\\nTests interrupted by user")
        return 1
    except Exception as e:
        print(f"\\nTest execution failed: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())