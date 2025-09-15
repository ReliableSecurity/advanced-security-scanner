#!/usr/bin/env python3
"""
API Server Testing Script
Tests all API endpoints for functionality
"""

import sys
import os
import asyncio
import time
import subprocess
import requests
import json
from concurrent.futures import ThreadPoolExecutor

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

class APITester:
    """Test suite for the API server"""
    
    def __init__(self):
        self.base_url = "http://localhost:8000"
        self.server_process = None
        
    def start_server(self):
        """Start the API server"""
        try:
            print("🚀 Starting API server...")
            self.server_process = subprocess.Popen(
                [sys.executable, "src/web/api_server.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=os.getcwd()
            )
            
            # Wait for server to start
            time.sleep(5)
            
            # Check if server is running
            try:
                response = requests.get(f"{self.base_url}/api/health", timeout=5)
                if response.status_code == 200:
                    print("✅ Server started successfully")
                    return True
            except:
                pass
                
            print("❌ Server failed to start")
            return False
            
        except Exception as e:
            print(f"❌ Server start error: {e}")
            return False
    
    def stop_server(self):
        """Stop the API server"""
        if self.server_process:
            print("🛑 Stopping server...")
            self.server_process.terminate()
            self.server_process.wait()
            self.server_process = None
    
    def test_health_endpoint(self):
        """Test /api/health endpoint"""
        try:
            print("🔍 Testing /api/health...")
            response = requests.get(f"{self.base_url}/api/health", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success") and "version" in data.get("data", {}):
                    print("✅ Health endpoint working")
                    print(f"   Version: {data['data']['version']}")
                    return True
            
            print("❌ Health endpoint failed")
            return False
            
        except Exception as e:
            print(f"❌ Health test error: {e}")
            return False
    
    def test_tools_endpoint(self):
        """Test /api/tools endpoint"""
        try:
            print("🔍 Testing /api/tools...")
            response = requests.get(f"{self.base_url}/api/tools", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    tools = data.get("data", {})
                    print("✅ Tools endpoint working")
                    print(f"   Available tools: {len(tools)}")
                    return True
            
            print("❌ Tools endpoint failed")
            print(f"   Status: {response.status_code}")
            print(f"   Response: {response.text[:200]}...")
            return False
            
        except Exception as e:
            print(f"❌ Tools test error: {e}")
            return False
    
    def test_profiles_endpoint(self):
        """Test /api/profiles endpoint"""
        try:
            print("🔍 Testing /api/profiles...")
            response = requests.get(f"{self.base_url}/api/profiles", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    profiles = data.get("data", {})
                    print("✅ Profiles endpoint working")
                    print(f"   Available profiles: {len(profiles)}")
                    return True
            
            print("❌ Profiles endpoint failed")
            return False
            
        except Exception as e:
            print(f"❌ Profiles test error: {e}")
            return False
    
    def test_scan_endpoint(self):
        """Test /api/scan endpoint (POST)"""
        try:
            print("🔍 Testing /api/scan (POST)...")
            
            scan_data = {
                "target": "example.com",
                "profile": "quick"
            }
            
            response = requests.post(
                f"{self.base_url}/api/scan",
                json=scan_data,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    scan_id = data.get("data", {}).get("scan_id")
                    print("✅ Scan endpoint working")
                    print(f"   Scan ID: {scan_id}")
                    return True
            
            print("❌ Scan endpoint failed")
            return False
            
        except Exception as e:
            print(f"❌ Scan test error: {e}")
            return False
    
    def test_scans_list_endpoint(self):
        """Test /api/scans endpoint (GET)"""
        try:
            print("🔍 Testing /api/scans...")
            response = requests.get(f"{self.base_url}/api/scans", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    scans = data.get("data", [])
                    print("✅ Scans list endpoint working")
                    print(f"   Total scans: {len(scans)}")
                    return True
            
            print("❌ Scans list endpoint failed")
            return False
            
        except Exception as e:
            print(f"❌ Scans list test error: {e}")
            return False
    
    def test_dashboard_endpoint(self):
        """Test main dashboard endpoint"""
        try:
            print("🔍 Testing dashboard (/)...")
            response = requests.get(f"{self.base_url}/", timeout=10)
            
            if response.status_code == 200 and "Advanced Security Scanner" in response.text:
                print("✅ Dashboard endpoint working")
                return True
            
            print("❌ Dashboard endpoint failed")
            return False
            
        except Exception as e:
            print(f"❌ Dashboard test error: {e}")
            return False
    
    def run_all_tests(self):
        """Run all API tests"""
        print("🧪 ADVANCED SECURITY SCANNER - API TESTING")
        print("=" * 50)
        
        if not self.start_server():
            return False
        
        try:
            tests = [
                ("Health Check", self.test_health_endpoint),
                ("Dashboard", self.test_dashboard_endpoint),
                ("Tools List", self.test_tools_endpoint),
                ("Profiles List", self.test_profiles_endpoint),
                ("Scan Start", self.test_scan_endpoint),
                ("Scans List", self.test_scans_list_endpoint)
            ]
            
            passed = 0
            total = len(tests)
            
            for test_name, test_func in tests:
                print(f"\n--- {test_name} ---")
                if test_func():
                    passed += 1
                time.sleep(1)  # Brief pause between tests
            
            print(f"\n{'='*50}")
            print(f"🧪 TESTING COMPLETE: {passed}/{total} tests passed")
            
            if passed == total:
                print("🎉 ALL TESTS PASSED! API is fully functional")
                return True
            else:
                print(f"⚠️  {total - passed} tests failed")
                return False
                
        finally:
            self.stop_server()

def main():
    """Main function"""
    tester = APITester()
    success = tester.run_all_tests()
    
    if success:
        print("\n✅ API Server is ready for production!")
        print("   Start server: python3 src/web/api_server.py")
        print("   Dashboard: http://localhost:8000")
        print("   API docs: http://localhost:8000/api/docs")
    else:
        print("\n❌ Some tests failed. Check server logs.")
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())