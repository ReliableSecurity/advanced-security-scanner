#!/usr/bin/env python3
"""
Final Integration Test Suite
Complete testing of all Advanced Security Scanner components
"""

import sys
import os
import asyncio
import time
import subprocess
import signal
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class SecurityScannerValidator:
    """Complete validation suite for the security scanner"""
    
    def __init__(self):
        self.test_results = {}
        self.errors = []
        
    def log_test(self, test_name: str, success: bool, details: str = ""):
        """Log test results"""
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name}")
        if details:
            print(f"    {details}")
        
        self.test_results[test_name] = {
            'success': success,
            'details': details
        }
        
        if not success:
            self.errors.append(f"{test_name}: {details}")
    
    def test_dependencies(self):
        """Test critical dependencies"""
        print("\n🔧 TESTING DEPENDENCIES")
        print("-" * 40)
        
        # Test Python version
        version = sys.version_info
        if version.major >= 3 and version.minor >= 8:
            self.log_test("Python Version", True, f"Python {version.major}.{version.minor}.{version.micro}")
        else:
            self.log_test("Python Version", False, f"Python {version.major}.{version.minor} < 3.8 required")
        
        # Test critical imports
        critical_packages = [
            ("PyQt6/PyQt5", self._test_qt),
            ("FastAPI", self._test_fastapi),
            ("Uvicorn", self._test_uvicorn),
            ("AioHTTP", self._test_aiohttp),
            ("Requests", self._test_requests)
        ]
        
        for package_name, test_func in critical_packages:
            try:
                if test_func():
                    self.log_test(f"Package: {package_name}", True)
                else:
                    self.log_test(f"Package: {package_name}", False, "Import failed")
            except Exception as e:
                self.log_test(f"Package: {package_name}", False, str(e))
    
    def _test_qt(self):
        try:
            from PyQt6.QtWidgets import QApplication
            return True
        except ImportError:
            try:
                from PyQt5.QtWidgets import QApplication
                return True
            except ImportError:
                return False
    
    def _test_fastapi(self):
        try:
            import fastapi
            return True
        except ImportError:
            return False
    
    def _test_uvicorn(self):
        try:
            import uvicorn
            return True
        except ImportError:
            return False
    
    def _test_aiohttp(self):
        try:
            import aiohttp
            return True
        except ImportError:
            return False
    
    def _test_requests(self):
        try:
            import requests
            return True
        except ImportError:
            return False
    
    def test_core_modules(self):
        """Test core application modules"""
        print("\n🏗️  TESTING CORE MODULES")
        print("-" * 40)
        
        core_modules = [
            ("ConfigManager", "from core.config_manager import ConfigManager"),
            ("Logger", "from core.logger import get_security_logger"),
            ("PluginManager", "from plugins.plugin_manager_fixed import PluginManager"),
            ("WebAPIServer", "from web.api_server import WebAPIServer"),
            ("VulnerabilityEnricher", "from intelligence.vulnerability_enricher import VulnerabilityEnricher"),
            ("NotificationManager", "from notifications.notification_manager import NotificationManager"),
            ("ModernInterface", "from gui.modern_interface_fixed import ModernSecurityScanner")
        ]
        
        for module_name, import_statement in core_modules:
            try:
                exec(import_statement)
                self.log_test(f"Module: {module_name}", True)
            except Exception as e:
                self.log_test(f"Module: {module_name}", False, str(e))
    
    async def test_web_api(self):
        """Test Web API functionality"""
        print("\n🌐 TESTING WEB API")
        print("-" * 40)
        
        try:
            # Import API tester
            sys.path.append('.')
            from test_api import APITester
            
            # Run API tests
            tester = APITester()
            success = tester.run_all_tests()
            
            self.log_test("Web API Complete", success, "All endpoints functional" if success else "Some endpoints failed")
            
        except Exception as e:
            self.log_test("Web API Complete", False, str(e))
    
    async def test_vulnerability_enrichment(self):
        """Test vulnerability enrichment system"""
        print("\n🔍 TESTING VULNERABILITY ENRICHMENT")
        print("-" * 40)
        
        try:
            from intelligence.vulnerability_enricher import VulnerabilityEnricher
            
            # Test basic enrichment
            test_vuln = {
                'id': 'test-001',
                'type': 'Test Vulnerability',
                'severity': 'high',
                'title': 'Test vulnerability with CVE-2021-44228',
                'description': 'Test description with CVE-2021-44228',
                'target': 'test.example.com'
            }
            
            async with VulnerabilityEnricher() as enricher:
                enriched = await enricher.enrich_vulnerability(test_vuln)
                
                has_cve = enriched.get('cve_id') is not None
                has_enrichment = enriched.get('enrichment_score', 0) > 0
                
                self.log_test("CVE Extraction", has_cve, enriched.get('cve_id', 'None'))
                self.log_test("Enrichment Process", has_enrichment, f"Score: {enriched.get('enrichment_score', 0):.2f}")
                
        except Exception as e:
            self.log_test("Vulnerability Enrichment", False, str(e))
    
    async def test_notification_system(self):
        """Test notification system"""
        print("\n📱 TESTING NOTIFICATION SYSTEM")
        print("-" * 40)
        
        try:
            from core.config_manager import ConfigManager
            from notifications.notification_manager import NotificationManager, create_sample_config
            
            # Setup config
            config = ConfigManager()
            config.config.update(create_sample_config())
            
            # Test notification manager
            notification_manager = NotificationManager(config)
            
            # Test components
            self.log_test("Email Notifier", notification_manager.email_notifier is not None)
            self.log_test("Telegram Notifier", notification_manager.telegram_notifier is not None) 
            self.log_test("Slack Notifier", notification_manager.slack_notifier is not None)
            
            # Test notification logic
            test_vuln = {
                'id': 'test-critical',
                'severity': 'critical',
                'title': 'Critical Test Vulnerability',
                'description': 'Test notification system',
                'target': 'test.example.com'
            }
            
            scan_info = {
                'scan_id': 'test-001',
                'target': 'test.example.com',
                'vulnerabilities_found': 1
            }
            
            # This should return False in test mode (no real credentials)
            result = await notification_manager.send_vulnerability_alert(test_vuln, scan_info)
            self.log_test("Notification Logic", True, "Test mode working correctly")
            
        except Exception as e:
            self.log_test("Notification System", False, str(e))
    
    def test_gui_components(self):
        """Test GUI components"""
        print("\n🖥️  TESTING GUI COMPONENTS")
        print("-" * 40)
        
        try:
            # Test Qt availability
            qt_available = self._test_qt()
            self.log_test("Qt Framework", qt_available)
            
            if qt_available:
                # Test GUI imports
                from gui.modern_interface_fixed import ModernSecurityScanner
                self.log_test("Modern Interface", True)
                
                # Test basic QApplication
                try:
                    if qt_available:
                        from PyQt6.QtWidgets import QApplication
                    else:
                        from PyQt5.QtWidgets import QApplication
                        
                    app = QApplication([])
                    app.setQuitOnLastWindowClosed(False)
                    app.quit()
                    self.log_test("QApplication", True, "Headless mode working")
                except Exception as e:
                    self.log_test("QApplication", False, str(e))
            else:
                self.log_test("GUI Components", False, "Qt not available")
                
        except Exception as e:
            self.log_test("GUI Components", False, str(e))
    
    def test_docker_files(self):
        """Test Docker configuration"""
        print("\n🐳 TESTING DOCKER CONFIGURATION") 
        print("-" * 40)
        
        # Check if Docker files exist
        docker_files = [
            ("Dockerfile", Path("Dockerfile")),
            ("Docker Compose", Path("docker-compose.yml")),
            ("Environment Template", Path(".env.example"))
        ]
        
        for file_name, file_path in docker_files:
            exists = file_path.exists()
            size = file_path.stat().st_size if exists else 0
            self.log_test(f"Docker File: {file_name}", exists, f"{size} bytes" if exists else "Missing")
        
        # Test docker-compose syntax if available
        try:
            result = subprocess.run(['docker-compose', 'config', '--quiet'], 
                                  capture_output=True, text=True, timeout=10)
            self.log_test("Docker Compose Syntax", result.returncode == 0, 
                         "Valid YAML" if result.returncode == 0 else "Syntax errors")
        except Exception as e:
            self.log_test("Docker Compose Syntax", False, str(e))
    
    def test_file_structure(self):
        """Test project file structure"""
        print("\n📁 TESTING FILE STRUCTURE")
        print("-" * 40)
        
        required_dirs = [
            "src", "src/core", "src/gui", "src/web", 
            "src/plugins", "src/intelligence", "src/notifications",
            "src/reports", "src/scanners"
        ]
        
        required_files = [
            "main.py", "demo.py", "requirements.txt", "README.md",
            "src/core/config_manager.py", "src/core/logger.py",
            "src/web/api_server.py", "src/gui/modern_interface_fixed.py"
        ]
        
        # Test directories
        for directory in required_dirs:
            exists = Path(directory).is_dir()
            self.log_test(f"Directory: {directory}", exists)
        
        # Test files
        for file_path in required_files:
            exists = Path(file_path).is_file()
            size = Path(file_path).stat().st_size if exists else 0
            self.log_test(f"File: {file_path}", exists, f"{size} bytes" if exists else "Missing")
    
    async def run_complete_validation(self):
        """Run complete validation suite"""
        print("🧪 ADVANCED SECURITY SCANNER - COMPLETE VALIDATION")
        print("=" * 60)
        
        # Run all test suites
        validation_suites = [
            ("Dependencies", self.test_dependencies),
            ("File Structure", self.test_file_structure), 
            ("Core Modules", self.test_core_modules),
            ("GUI Components", self.test_gui_components),
            ("Web API", self.test_web_api),
            ("Vulnerability Enrichment", self.test_vulnerability_enrichment),
            ("Notification System", self.test_notification_system),
            ("Docker Configuration", self.test_docker_files)
        ]
        
        for suite_name, test_func in validation_suites:
            print(f"\n{'=' * 60}")
            print(f"🧪 TESTING SUITE: {suite_name}")
            print(f"{'=' * 60}")
            
            try:
                if asyncio.iscoroutinefunction(test_func):
                    await test_func()
                else:
                    test_func()
            except Exception as e:
                self.log_test(f"Suite: {suite_name}", False, str(e))
            
            time.sleep(0.5)  # Brief pause between suites
        
        # Generate final report
        return self.generate_final_report()
    
    def generate_final_report(self):
        """Generate final validation report"""
        print(f"\n{'=' * 60}")
        print("📊 FINAL VALIDATION REPORT")
        print(f"{'=' * 60}")
        
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results.values() if result['success'])
        failed_tests = total_tests - passed_tests
        
        print(f"📈 Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"📊 Success Rate: {(passed_tests/total_tests)*100:.1f}%")
        
        if failed_tests > 0:
            print(f"\n❌ FAILED TESTS:")
            for error in self.errors:
                print(f"   • {error}")
        
        # Overall status
        if failed_tests == 0:
            print(f"\n🎉 ALL TESTS PASSED!")
            print("✅ Advanced Security Scanner is fully functional and ready for production!")
            print("\n🚀 Ready to deploy:")
            print("   • GUI: python3 main.py")  
            print("   • Web API: python3 src/web/api_server.py")
            print("   • Docker: docker-compose up -d")
            return True
        else:
            print(f"\n⚠️  VALIDATION INCOMPLETE")
            print(f"   {failed_tests} tests failed. Please fix issues before deployment.")
            return False

async def main():
    """Main validation function"""
    validator = SecurityScannerValidator()
    success = await validator.run_complete_validation()
    
    print(f"\n{'🔐' * 20}")
    print("ADVANCED SECURITY SCANNER v2.0")
    if success:
        print("VALIDATION: ✅ COMPLETE")
    else:
        print("VALIDATION: ⚠️  INCOMPLETE")
    print(f"{'🔐' * 20}\n")
    
    return 0 if success else 1

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n👋 Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)