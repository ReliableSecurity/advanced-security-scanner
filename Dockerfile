# Advanced Security Scanner Docker Image
FROM kalilinux/kali-rolling:latest

LABEL maintainer="Security Team"
LABEL description="Advanced Security Scanner with 50+ integrated tools"
LABEL version="2.0.0"

# Environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV SCANNER_HOME=/opt/security-scanner
ENV SCANNER_USER=scanner
ENV SCANNER_GROUP=scanner

# Install system dependencies and security tools
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    # Build essentials
    build-essential \
    pkg-config \
    git \
    curl \
    wget \
    unzip \
    # Python and development
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    # GUI libraries (for headless operation)
    xvfb \
    x11-utils \
    # Qt libraries
    qt6-base-dev \
    python3-pyqt6 \
    python3-pyqt6.qtwebengine \
    python3-pyqt6.qtopengl \
    # Graphics libraries
    libgl1-mesa-dev \
    libglib2.0-dev \
    libjpeg-dev \
    libpng-dev \
    # SSL/Crypto
    libssl-dev \
    libffi-dev \
    # Security scanning tools
    nmap \
    nikto \
    sqlmap \
    dirb \
    gobuster \
    wapiti \
    whatweb \
    masscan \
    zaproxy \
    hydra \
    john \
    hashcat \
    aircrack-ng \
    # Additional utilities
    dnsutils \
    netcat-traditional \
    telnet \
    whois \
    traceroute \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go for additional tools
RUN curl -OL https://golang.org/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

# Install Go-based security tools
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
    mv /root/go/bin/* /usr/local/bin/ && \
    rm -rf /root/go

# Update Nuclei templates
RUN nuclei -update-templates

# Create scanner user and group
RUN groupadd -r ${SCANNER_GROUP} && \
    useradd -r -g ${SCANNER_GROUP} -d ${SCANNER_HOME} -s /bin/bash ${SCANNER_USER}

# Create application directory
RUN mkdir -p ${SCANNER_HOME} && \
    chown -R ${SCANNER_USER}:${SCANNER_GROUP} ${SCANNER_HOME}

# Switch to scanner user
USER ${SCANNER_USER}
WORKDIR ${SCANNER_HOME}

# Copy application files
COPY --chown=${SCANNER_USER}:${SCANNER_GROUP} . ${SCANNER_HOME}/

# Create virtual environment and install Python dependencies
RUN python3 -m venv venv && \
    . venv/bin/activate && \
    pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Create necessary directories
RUN mkdir -p logs reports output data temp config/profiles plugins/custom

# Copy configuration templates
COPY --chown=${SCANNER_USER}:${SCANNER_GROUP} docker/config/ config/

# Make scripts executable
RUN chmod +x setup.sh demo.py main.py src/web/api_server.py

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Expose ports
EXPOSE 8000 8080

# Environment variables for runtime
ENV DISPLAY=:99
ENV QT_QPA_PLATFORM=offscreen

# Volume mounts
VOLUME ["/opt/security-scanner/logs", "/opt/security-scanner/reports", "/opt/security-scanner/config"]

# Start command - can be overridden
CMD ["./venv/bin/python3", "src/web/api_server.py"]