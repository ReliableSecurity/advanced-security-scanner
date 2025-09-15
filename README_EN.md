# 🔐 Advanced Security Scanner

A comprehensive, AI-powered security scanning platform with modern Material Design GUI, featuring 50+ integrated security tools, machine learning vulnerability analysis, and enterprise-grade reporting.

## ✨ Features

### 🔧 Core Security Features
- **Multi-threaded scanning** - Concurrent execution of multiple security tools
- **50+ integrated tools** including Nmap, Nikto, SQLMap, Nuclei, Gobuster, and more
- **OWASP WSTG compliance** - Full Web Security Testing Guide coverage
- **API security assessment** - REST, GraphQL, and SOAP endpoint testing
- **Network infrastructure scanning** - Port scanning, service enumeration
- **Web application testing** - XSS, SQL injection, CSRF detection
- **Vulnerability management** - CVE mapping and CVSS scoring

### 🤖 AI-Powered Analysis
- **Machine learning classification** - Automated vulnerability categorization
- **Risk scoring algorithms** - Dynamic CVSS-based risk assessment
- **False positive detection** - ML models to reduce noise
- **Intelligent prioritization** - Smart vulnerability ranking
- **Automated recommendations** - AI-generated remediation guidance
- **Threat intelligence integration** - Real-time threat data correlation

### 🎨 Modern Material Design Interface
- **Material Design 3** - Latest Google Material Design standards
- **3D visualizations** - OpenGL-powered vulnerability mapping
- **Interactive charts** - Real-time data visualization with Plotly
- **Dark/light themes** - Adaptive UI themes
- **Responsive design** - Works on various screen sizes
- **Progressive Web App** features for enhanced usability

### 📊 Advanced Reporting System
- **Interactive HTML reports** - Rich, clickable vulnerability reports
- **PDF executive summaries** - Management-ready documentation
- **JSON data exports** - API-friendly structured data
- **Real-time dashboards** - Live scanning progress and metrics
- **SIEM integration** - Export formats for security platforms
- **Custom report templates** - Branded and customizable outputs

### 🔌 Extensible Plugin Architecture
- **Plugin system** - Easy integration of custom security tools
- **REST API** - Programmatic access to all features
- **WebSocket support** - Real-time updates and notifications
- **Configuration management** - Flexible tool and profile configuration
- **Workflow automation** - Scriptable scanning workflows

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Linux/macOS/Windows (Kali Linux recommended)
- 4GB RAM minimum (8GB recommended)
- 2GB disk space

### Installation

#### Option 1: Automated Setup (Recommended)
```bash
# Clone the repository
git clone <repository-url>
cd security-scanner

# Run automated setup
./setup.sh

# Activate virtual environment
source venv/bin/activate
```

#### Option 2: Manual Installation
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
    build-essential qt6-base-dev python3-pyqt6 \
    nmap nikto sqlmap nuclei dirb gobuster

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### First Run

1. **Run the demo** to verify installation:
```bash
python3 demo.py
```

2. **Launch the standard GUI**:
```bash
python3 main.py
```

3. **Launch the modern Material Design GUI**:
```bash
python3 src/gui/modern_interface_fixed.py
```

## 📖 Usage Guide

### Basic Scanning

1. **Target Configuration**
   - Enter IP address, hostname, or CIDR range
   - Select scan profile (Quick, Standard, Comprehensive)
   - Configure tool preferences

2. **Scan Execution**
   - Choose from 50+ available security tools
   - Monitor real-time progress in the dashboard
   - View live vulnerability discoveries

3. **Results Analysis**
   - AI-powered vulnerability classification
   - Risk scoring and prioritization
   - Interactive 3D visualization
   - Detailed remediation recommendations

4. **Report Generation**
   - Export to HTML, PDF, or JSON
   - Share with stakeholders
   - Integrate with SIEM platforms

### Advanced Features

#### Custom Plugins
Create custom security tool integrations:

```python
# plugins/custom/my_scanner.py
from plugins.base_plugin import BasePlugin

class MyScanner(BasePlugin):
    def __init__(self):
        super().__init__("my_scanner", "Custom Scanner")
    
    async def scan(self, target, options):
        # Your custom scanning logic
        vulnerabilities = []
        return vulnerabilities
```

#### API Integration
Access scanner features programmatically:

```python
import requests

# Start scan
response = requests.post('http://localhost:8000/api/scan', json={
    'target': '192.168.1.0/24',
    'profile': 'comprehensive'
})

# Get results
scan_id = response.json()['scan_id']
results = requests.get(f'http://localhost:8000/api/results/{scan_id}')
```

#### Configuration Management
Customize tool behavior:

```yaml
# config/profiles/custom.yaml
name: "Custom Profile"
description: "My custom scanning profile"
tools:
  nmap:
    enabled: true
    options: "-sS -sV -A"
  nuclei:
    enabled: true
    options: "-severity critical,high"
```

## 🛠 Configuration

### Tool Configuration
Individual tool settings in `config/tools/`:
- `nmap.yaml` - Port scanning configuration
- `nikto.yaml` - Web server testing options
- `sqlmap.yaml` - SQL injection testing parameters
- `nuclei.yaml` - Template-based vulnerability scanning

### Scan Profiles
Pre-configured scan profiles in `config/profiles/`:
- `quick.yaml` - Fast reconnaissance scan
- `standard.yaml` - Balanced security assessment
- `comprehensive.yaml` - Thorough security audit
- `web_apps.yaml` - Web application focused
- `infrastructure.yaml` - Network infrastructure focus

### AI Model Configuration
Machine learning settings in `config/ai_config.yaml`:
- Model selection and parameters
- Training data sources
- Classification thresholds
- False positive reduction settings

## 📊 Reporting

### Report Types

1. **Executive Summary** - High-level risk overview for management
2. **Technical Report** - Detailed vulnerability analysis for technical teams  
3. **Compliance Report** - OWASP, NIST, ISO 27001 compliance mapping
4. **Remediation Guide** - Step-by-step fixing instructions
5. **Raw Data Export** - JSON/CSV for further analysis

### Report Customization
- Custom branding and logos
- Configurable risk matrices
- Template customization
- Multi-format export options

## 🧪 Testing

Run the comprehensive test suite:

```bash
# Run all tests
python3 comprehensive_test.py

# Test specific components
python3 -m pytest tests/test_plugins.py
python3 -m pytest tests/test_gui.py
python3 -m pytest tests/test_scanners.py
```

### Test Coverage
- Unit tests for all core components
- Integration tests for tool interfaces
- GUI automated testing
- Performance benchmarking
- Security validation tests

## 🔧 Development

### Project Structure
```
security-scanner/
├── src/
│   ├── core/           # Core functionality
│   ├── gui/            # User interfaces
│   ├── scanners/       # Security tool integrations
│   ├── plugins/        # Plugin system
│   └── reports/        # Report generation
├── config/             # Configuration files
├── tests/              # Test suites
├── docs/               # Documentation
├── logs/               # Application logs
├── reports/            # Generated reports
└── requirements.txt    # Python dependencies
```

### Contributing
1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit pull request

### Code Style
- Follow PEP 8 guidelines
- Use type hints
- Comprehensive docstrings
- Error handling and logging
- Security-first design principles

## 🛡 Security Considerations

### Safe Usage
- **Test environment first** - Always test on non-production systems
- **Authorization required** - Only scan systems you own or have permission to test
- **Rate limiting** - Built-in protections against overwhelming targets
- **Credential management** - Secure handling of authentication data
- **Network isolation** - Consider running in isolated network segments

### Data Privacy
- **No data collection** - All scanning data remains local
- **Encrypted storage** - Sensitive data encrypted at rest
- **Audit logging** - Complete activity logging for compliance
- **Access controls** - Role-based access to scan results

## 📈 Performance

### System Requirements
- **Minimum**: 4GB RAM, 2 CPU cores, 2GB disk
- **Recommended**: 8GB RAM, 4 CPU cores, 10GB disk
- **Optimal**: 16GB RAM, 8 CPU cores, 50GB SSD

### Optimization Tips
- Use SSD storage for better I/O performance
- Configure concurrent scan limits based on system resources
- Monitor memory usage with large target ranges
- Use profile-specific tool selections to reduce resource usage

### Benchmarks
- **Quick scan**: ~5 minutes for single host
- **Standard scan**: ~30 minutes for single host  
- **Comprehensive scan**: ~2-4 hours for single host
- **Network range**: Scales linearly with concurrent limits

## 🤝 Support

### Documentation
- **User Manual**: `docs/user_manual.md`
- **API Documentation**: `docs/api.md`
- **Plugin Development**: `docs/plugin_guide.md`
- **Troubleshooting**: `docs/troubleshooting.md`

### Community
- GitHub Issues for bug reports and feature requests
- Discussions for questions and community support
- Security vulnerabilities via responsible disclosure

### Professional Support
- Enterprise consulting available
- Custom development services
- Training and certification programs
- SLA-backed support options

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **OWASP** - Web security testing methodology
- **NIST** - Cybersecurity framework guidance
- **Security community** - Tool authors and vulnerability researchers
- **Open source contributors** - Libraries and frameworks used

---

**⚠️ Important Notice**: This tool is for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any systems. Unauthorized use may be illegal in your jurisdiction.

**🔐 Happy Scanning!** - Built with ❤️ for the security community