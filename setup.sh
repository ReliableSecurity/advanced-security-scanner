#!/bin/bash

# Security Scanner Setup Script
# Installs all dependencies and prepares the environment

set -e

echo "🔐 ADVANCED SECURITY SCANNER SETUP"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (not recommended for most operations)
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. Some package installations may require user permissions."
fi

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt-get &> /dev/null; then
        OS="debian"
        PACKAGE_MANAGER="apt-get"
    elif command -v yum &> /dev/null; then
        OS="rhel"
        PACKAGE_MANAGER="yum"
    elif command -v pacman &> /dev/null; then
        OS="arch"
        PACKAGE_MANAGER="pacman"
    else
        OS="unknown"
        print_warning "Unknown Linux distribution. Manual dependency installation may be required."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    PACKAGE_MANAGER="brew"
else
    OS="unknown"
    print_warning "Unsupported OS. Manual setup required."
fi

print_status "Detected OS: $OS"

# Update system packages
print_status "Updating system packages..."
case $OS in
    "debian")
        sudo apt-get update -qq
        ;;
    "rhel")
        sudo yum update -y -q
        ;;
    "arch")
        sudo pacman -Sy --noconfirm
        ;;
    "macos")
        if ! command -v brew &> /dev/null; then
            print_error "Homebrew not found. Please install Homebrew first."
            exit 1
        fi
        brew update
        ;;
esac

# Install system dependencies
print_status "Installing system dependencies..."
case $OS in
    "debian")
        sudo apt-get install -y python3 python3-pip python3-venv python3-dev \
            build-essential pkg-config libgl1-mesa-dev libglib2.0-dev \
            qt6-base-dev python3-pyqt6 python3-pyqt6.qtwebengine \
            python3-pyqt6.qtopengl python3-pyqt6.qtcharts \
            libssl-dev libffi-dev libjpeg-dev libpng-dev \
            git curl wget nmap nikto sqlmap nuclei dirb gobuster \
            masscan zap hydra john hashcat aircrack-ng metasploit-framework 2>/dev/null || {
                print_warning "Some security tools may not be available in repositories"
            }
        ;;
    "rhel")
        sudo yum install -y python3 python3-pip python3-devel gcc gcc-c++ \
            qt6-qtbase-devel python3-qt6 openssl-devel libffi-devel \
            libjpeg-devel libpng-devel git curl wget nmap 2>/dev/null || {
                print_warning "Some packages may not be available"
            }
        ;;
    "arch")
        sudo pacman -S --noconfirm python python-pip python-virtualenv \
            base-devel qt6-base python-pyqt6 python-pyqt6-webengine \
            openssl libffi libjpeg-turbo libpng git curl wget nmap 2>/dev/null || {
                print_warning "Some packages may not be available"
            }
        ;;
    "macos")
        brew install python3 qt6 openssl libffi jpeg libpng git curl wget nmap 2>/dev/null || {
                print_warning "Some packages may not be available via Homebrew"
            }
        ;;
esac

# Check Python version
print_status "Checking Python version..."
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
print_success "Python version: $PYTHON_VERSION"

if [[ $(echo "$PYTHON_VERSION < 3.8" | bc -l 2>/dev/null || echo "1") == "1" ]]; then
    print_error "Python 3.8+ required. Current version: $PYTHON_VERSION"
    exit 1
fi

# Create virtual environment
print_status "Setting up Python virtual environment..."
if [[ ! -d "venv" ]]; then
    python3 -m venv venv
    print_success "Virtual environment created"
else
    print_success "Virtual environment already exists"
fi

# Activate virtual environment
source venv/bin/activate
print_success "Virtual environment activated"

# Upgrade pip
print_status "Upgrading pip..."
pip install --upgrade pip setuptools wheel

# Install Python dependencies
print_status "Installing Python dependencies..."
if [[ -f "requirements.txt" ]]; then
    pip install -r requirements.txt
    print_success "Python dependencies installed"
else
    print_warning "requirements.txt not found. Installing core dependencies..."
    pip install PyQt6 PyQt6-WebEngine numpy pandas matplotlib plotly dash \
                tensorflow scikit-learn transformers torch torchvision \
                requests aiohttp beautifulsoup4 lxml pyyaml python-dateutil \
                jinja2 reportlab seaborn PyOpenGL cryptography paramiko \
                python-nmap python-masscan psutil netifaces
fi

# Create necessary directories
print_status "Creating project directories..."
mkdir -p logs reports output plugins/custom config/profiles data temp

# Set up logging directory permissions
chmod 755 logs
chmod 755 reports
chmod 755 output

print_success "Directory structure created"

# Download and update security tool templates/configs (if needed)
print_status "Setting up security tool configurations..."

# Create basic config files if they don't exist
if [[ ! -f "config/main_config.yaml" ]]; then
    cat > config/main_config.yaml << 'EOF'
# Main configuration file
app:
  name: "Advanced Security Scanner"
  version: "2.0.0"
  debug: false

logging:
  level: "INFO"
  file: "logs/security_scanner.log"
  max_size_mb: 50
  backup_count: 5

scanning:
  max_concurrent_scans: 5
  default_timeout: 300
  max_retries: 3

reporting:
  output_dir: "reports"
  formats: ["html", "json", "pdf"]
  include_raw_data: true

plugins:
  auto_load: true
  custom_path: "plugins/custom"
EOF
    print_success "Main configuration file created"
fi

# Install additional security tools (if available)
print_status "Installing additional security tools..."

# Install Go tools (if Go is available)
if command -v go &> /dev/null; then
    print_status "Installing Go-based security tools..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest 2>/dev/null || print_warning "Nuclei installation failed"
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || print_warning "HTTPx installation failed"
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || print_warning "Subfinder installation failed"
else
    print_warning "Go not found. Some tools may not be available."
fi

# Test core functionality
print_status "Testing core functionality..."
python3 -c "
try:
    import sys
    sys.path.insert(0, 'src')
    
    # Test core imports
    from core.config_manager import ConfigManager
    from core.logger import get_security_logger
    print('✓ Core modules working')
    
    # Test GUI imports
    try:
        from PyQt6.QtWidgets import QApplication
        from gui.modern_interface_fixed import ModernSecurityScanner
        print('✓ Modern GUI available')
    except ImportError as e:
        try:
            from PyQt5.QtWidgets import QApplication
            print('✓ PyQt5 fallback available')
        except ImportError:
            print('⚠ GUI modules unavailable')
    
    # Test ML imports
    try:
        import numpy, sklearn
        print('✓ AI/ML modules available')
    except ImportError:
        print('⚠ AI/ML modules unavailable (basic functionality will work)')
        
    print('✓ Setup validation completed')
    
except Exception as e:
    print(f'✗ Setup validation failed: {e}')
    exit(1)
" && print_success "Core functionality test passed" || print_error "Core functionality test failed"

# Final setup steps
print_status "Final setup steps..."

# Make scripts executable
chmod +x demo.py 2>/dev/null || true
chmod +x main.py 2>/dev/null || true

# Create desktop shortcut (Linux only)
if [[ "$OS" == "debian" ]] && command -v desktop-file-install &> /dev/null; then
    CURRENT_DIR=$(pwd)
    cat > security-scanner.desktop << EOF
[Desktop Entry]
Name=Security Scanner
Comment=Advanced Security Scanner with AI Analysis
Exec=$CURRENT_DIR/venv/bin/python3 $CURRENT_DIR/main.py
Icon=application-x-executable
Terminal=false
Type=Application
Categories=Security;Development;
EOF
    print_success "Desktop shortcut created"
fi

echo ""
echo "=================================="
print_success "🎉 SETUP COMPLETED SUCCESSFULLY! 🎉"
echo "=================================="
echo ""
echo "Next steps:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run the demo:                 python3 demo.py"
echo "3. Launch the GUI:               python3 main.py"
echo "4. Modern GUI:                   python3 src/gui/modern_interface_fixed.py"
echo ""
echo "Available tools and features:"
echo "• 50+ integrated security tools"
echo "• AI-powered vulnerability analysis" 
echo "• Material Design GUI interface"
echo "• Advanced reporting system"
echo "• Plugin architecture"
echo "• Real-time 3D visualizations"
echo ""
echo "For help and documentation:"
echo "• Run: python3 demo.py --help"
echo "• Check: README.md and docs/ directory"
echo ""
print_success "Happy scanning! 🔐"