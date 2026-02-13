#!/bin/bash

##############################################################################
# Elite Rama Proxy - Auto Installer 2026
# 100% Automated Installation for Production VPS
#
# Usage:
#   sudo bash install.sh              # Interactive install
#   sudo bash install.sh --uninstall  # Remove everything
#   sudo bash install.sh --help       # Show help
##############################################################################

set -euo pipefail  # Exit on error, undefined vars, and pipeline failures

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/rama-proxy"
SERVICE_USER="rama-proxy"
ADMIN_PASSWORD=""
AUTO_MODE=0
FORCE_REINSTALL=0
AUTO_DOMAIN=""
AUTO_ADMIN_PASSWORD=""
TOTAL_STEPS=14
CURRENT_STEP=0

##############################################################################
# Helper Functions
##############################################################################

step() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    echo ""
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}  Step ${CURRENT_STEP}/${TOTAL_STEPS}: $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

log_info() {
    echo -e "  ${BLUE}ℹ${NC}  $1"
}

log_success() {
    echo -e "  ${GREEN}✔${NC}  $1"
}

log_warn() {
    echo -e "  ${YELLOW}⚠${NC}  $1"
}

log_error() {
    echo -e "  ${RED}✖${NC}  $1"
}

ensure_rust_toolchain() {
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
    fi

    if ! command -v rustc &> /dev/null || ! command -v cargo &> /dev/null; then
        log_error "Rust toolchain not found (rustc/cargo)."
        log_info "Install Rust with rustup or distro packages, then re-run installer."
        exit 1
    fi
}

check_existing_installation() {
    if [ -d "$INSTALL_DIR" ] || [ -f "/etc/systemd/system/rama-proxy.service" ]; then
        log_warn "Existing installation detected (${INSTALL_DIR} and/or systemd service)."

        if [ "$FORCE_REINSTALL" -eq 1 ] || [ "$AUTO_MODE" -eq 1 ]; then
            log_warn "Proceeding with reinstall (existing files may be overwritten)."
            return
        fi

        echo ""
        read -p "Continue and overwrite existing installation? [y/N] " overwrite_confirm
        case "${overwrite_confirm:-N}" in
            [Yy]*) ;;
            *)
                echo "Installation cancelled."
                exit 0
                ;;
        esac
    fi
}

# Spinner for long-running commands
spinner() {
    local pid=$1
    local label=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${BLUE}${spin:$((i % 10)):1}${NC}  %s..." "$label"
        i=$((i + 1))
        sleep 0.2
    done
    set +e
    wait "$pid"
    local exit_code=$?
    set -e
    printf "\r"
    if [ $exit_code -eq 0 ]; then
        log_success "$label"
    else
        log_error "$label (exit code: $exit_code)"
        return $exit_code
    fi
}

##############################################################################
# Help & Uninstall
##############################################################################

show_help() {
    echo ""
    echo -e "${BOLD}Elite Rama Proxy — Auto Installer${NC}"
    echo ""
    echo "Usage:"
    echo "  sudo bash install.sh              Interactive installation"
    echo "  sudo bash install.sh --auto       Non-interactive installation"
    echo "  sudo bash install.sh --auto --domain proxy.example.com"
    echo "  sudo bash install.sh --auto --admin-password 'StrongPass123!'"
    echo "  sudo bash install.sh --auto --force"
    echo "  sudo bash install.sh --uninstall  Remove proxy and all data"
    echo "  sudo bash install.sh --help       Show this help"
    echo ""
    echo "What the installer does:"
    echo "  1. Installs system dependencies (curl, git, gcc, pkg-config)"
    echo "  2. Installs Rust (if not already installed)"
    echo "  3. Compiles the proxy from source (~5-15 min)"
    echo "  4. Asks you to set an admin password"
    echo "  5. Generates SSL certificates (self-signed or for your domain)"
    echo "  6. Creates a systemd service (auto-start on boot)"
    echo "  7. Configures firewall rules"
    echo "  8. Tests that everything works"
    echo ""
    echo "After installation:"
    echo "  Admin panel → https://YOUR_IP:8443/admin_elite/login"
    echo "  Credentials → /opt/rama-proxy/CREDENTIALS.txt"
    echo ""
    echo "Requirements:"
    echo "  OS: Ubuntu 20+, Debian 11+ (recommended), Fedora 38+, CentOS/RHEL 8+, Rocky, AlmaLinux"
    echo "  RAM: 2 GB minimum (for Rust compilation)"
    echo "  Disk: 5 GB free space"
    echo ""
    exit 0
}

uninstall() {
    echo ""
    echo -e "${BOLD}${RED}Uninstalling Elite Rama Proxy${NC}"
    echo ""
    
    echo -e "${YELLOW}This will remove:${NC}"
    echo "  • Systemd service (rama-proxy)"
    echo "  • Installation directory (${INSTALL_DIR})"
    echo "  • Service user (${SERVICE_USER})"
    echo "  • Log rotation config"
    echo ""
    read -p "Are you sure? Type YES to confirm: " confirm
    
    if [ "$confirm" != "YES" ]; then
        echo "Uninstall cancelled."
        exit 0
    fi
    
    echo ""
    
    # Stop and disable service
    if systemctl is-active --quiet rama-proxy 2>/dev/null; then
        systemctl stop rama-proxy
        log_success "Service stopped"
    fi
    if systemctl is-enabled --quiet rama-proxy 2>/dev/null; then
        systemctl disable rama-proxy
        log_success "Service disabled"
    fi
    rm -f /etc/systemd/system/rama-proxy.service
    systemctl daemon-reload 2>/dev/null || true
    log_success "Systemd service removed"
    
    # Remove log rotation
    rm -f /etc/logrotate.d/rama-proxy
    log_success "Log rotation config removed"
    
    # Remove install directory
    if [ -d "$INSTALL_DIR" ]; then
        rm -rf "$INSTALL_DIR"
        log_success "Installation directory removed: ${INSTALL_DIR}"
    fi
    
    # Remove service user
    if id "$SERVICE_USER" &>/dev/null; then
        userdel "$SERVICE_USER" 2>/dev/null || true
        log_success "Service user removed: ${SERVICE_USER}"
    fi
    
    echo ""
    log_success "Uninstallation complete."
    echo ""
    log_info "Rust toolchain was NOT removed. To remove it: rustup self uninstall"
    echo ""
    exit 0
}

##############################################################################
# System Detection
##############################################################################

detect_os() {
    OS_VERSION="unknown"

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    
    log_success "Detected OS: ${BOLD}$OS $OS_VERSION${NC}"
}

##############################################################################
# Check Root
##############################################################################

check_root_simple() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        echo "Run: sudo bash install.sh"
        exit 1
    fi
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Please run: ${BOLD}sudo bash install.sh${NC}"
        exit 1
    fi
}

##############################################################################
# Pre-flight Checks
##############################################################################

preflight_checks() {
    local issues=0
    
    # Check RAM (need ~2GB for Rust compilation)
    local ram_mb
    ram_mb=$(free -m 2>/dev/null | awk '/^Mem:/{print $2}' || echo "0")
    if [ "$ram_mb" -lt 1500 ]; then
        log_error "Insufficient RAM: ${ram_mb}MB detected, need at least 2GB"
        log_info "Tip: Add swap space with: fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile"
        issues=$((issues + 1))
    else
        log_success "RAM: ${ram_mb}MB (OK)"
    fi
    
    # Check available disk space (need ~5GB for compilation)
    local disk_gb
    disk_gb=$(df -BG / 2>/dev/null | awk 'NR==2{gsub("G",""); print $4}' || echo "0")
    if [ "$disk_gb" -lt 5 ]; then
        log_error "Insufficient disk space: ${disk_gb}GB free, need at least 5GB"
        issues=$((issues + 1))
    else
        log_success "Disk space: ${disk_gb}GB free (OK)"
    fi
    
    # Check internet connectivity
    if curl -s --connect-timeout 5 https://crates.io > /dev/null 2>&1; then
        log_success "Internet connectivity (OK)"
    else
        log_error "Cannot reach https://crates.io — internet required for installation"
        issues=$((issues + 1))
    fi
    
    if [ "$issues" -gt 0 ]; then
        echo ""
        log_error "$issues pre-flight check(s) failed. Fix the issues above and re-run."
        exit 1
    fi
}

##############################################################################
# Install Dependencies
##############################################################################

install_dependencies() {
    # NOTE: No cmake/clang/openssl-dev needed — we use pure Rust TLS (rustls + ring)
    # openssl CLI is only used for self-signed cert generation in the installer
    
    case "$OS" in
        ubuntu|debian)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update -qq
            apt-get install -y -qq \
                curl git build-essential pkg-config \
                openssl ca-certificates > /dev/null 2>&1
            ;;
        fedora)
            dnf install -y -q \
                curl git gcc gcc-c++ make pkg-config \
                openssl ca-certificates > /dev/null 2>&1
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y -q \
                curl git gcc gcc-c++ make pkg-config \
                openssl ca-certificates > /dev/null 2>&1
            ;;
        *)
            log_error "Unsupported OS: $OS"
            log_info "Supported: Ubuntu, Debian, Fedora, CentOS, RHEL, Rocky, AlmaLinux"
            exit 1
            ;;
    esac
    
    log_success "System dependencies installed"
}

##############################################################################
# Install Rust
##############################################################################

install_rust() {
    log_info "Installing Rust..."
    
    if command -v rustc &> /dev/null && command -v cargo &> /dev/null; then
        log_warn "Rust already installed: $(rustc --version)"
        return
    fi
    
    # Install Rust for root (will be used to compile)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    ensure_rust_toolchain
    
    # Verify installation
    if ! command -v rustc &> /dev/null; then
        log_error "Failed to install Rust"
        exit 1
    fi
    
    log_success "Rust installed: $(rustc --version)"
}

##############################################################################
# Create Service User
##############################################################################

create_service_user() {
    log_info "Creating service user: $SERVICE_USER"
    
    if id "$SERVICE_USER" &>/dev/null; then
        log_warn "User $SERVICE_USER already exists"
    else
        useradd -r -s /bin/false -d /nonexistent -M "$SERVICE_USER"
        log_success "Service user created"
    fi
}

##############################################################################
# Compile Project
##############################################################################

compile_project() {
    log_info "This is the slowest step — usually 5-15 minutes depending on your server."
    log_info "Compilation log: /tmp/rama-compile.log"
    
    cd "$SCRIPT_DIR"

    ensure_rust_toolchain
    
    # Build release version with spinner (hide cargo noise)
    cargo build --release > /tmp/rama-compile.log 2>&1 &
    spinner $! "Compiling (be patient, this takes a while)"
    
    if [ ! -f "target/release/rama-elite-proxy" ]; then
        log_error "Compilation failed! Check /tmp/rama-compile.log for details"
        log_info "Common fix: ensure you have at least 2GB RAM (or add swap)"
        exit 1
    fi
    
    local bin_size
    bin_size=$(du -h "target/release/rama-elite-proxy" | cut -f1)
    log_success "Binary compiled: ${bin_size}"
}

##############################################################################
# Generate Admin Password
##############################################################################

generate_admin_password() {
    log_info "Admin password configuration..."
    echo ""

    if [ -n "$AUTO_ADMIN_PASSWORD" ]; then
        if [ ${#AUTO_ADMIN_PASSWORD} -lt 12 ]; then
            log_error "--admin-password must be at least 12 characters"
            exit 1
        fi

        ADMIN_PASSWORD="$AUTO_ADMIN_PASSWORD"
        log_success "Admin password set from --admin-password"
        return
    fi

    if [ "$AUTO_MODE" -eq 1 ]; then
        ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
        log_success "Auto mode: random admin password generated"
        return
    fi
    
    # Ask user if they want to set custom password
    echo -e "${YELLOW}Choose password option:${NC}"
    echo "  1) Generate random secure password (recommended)"
    echo "  2) Set custom password"
    echo ""
    read -p "Enter choice [1-2]: " password_choice
    
    case "$password_choice" in
        2)
            # Custom password
            while true; do
                echo ""
                read -sp "Enter admin password (min 12 chars): " pass1
                echo ""
                
                if [ ${#pass1} -lt 12 ]; then
                    log_error "Password must be at least 12 characters!"
                    continue
                fi
                
                read -sp "Confirm password: " pass2
                echo ""
                
                if [ "$pass1" != "$pass2" ]; then
                    log_error "Passwords don't match!"
                    continue
                fi
                
                ADMIN_PASSWORD="$pass1"
                log_success "Custom password set"
                break
            done
            ;;
        *)
            # Generate random password (default)
            ADMIN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-20)
            log_success "Random password generated: ${YELLOW}${ADMIN_PASSWORD}${NC}"
            echo ""
            log_warn "SAVE THIS PASSWORD NOW!"
            sleep 3
            ;;
    esac
}

##############################################################################
# Generate Password Hash
##############################################################################

generate_password_hash() {
    log_info "Generating password hash..."

    ensure_rust_toolchain
    
    cd "$SCRIPT_DIR"
    
    # Create temporary hash generator if example doesn't exist
    if [ ! -f "examples/hash_password.rs" ]; then
        mkdir -p examples
        cat > examples/hash_password.rs << 'EOF'
use rama_elite_proxy::auth::AuthManager;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: hash_password <password>");
        std::process::exit(1);
    }
    let password = &args[1];
    let hash = AuthManager::hash_password(password);
    println!("{}", hash);
}
EOF
    fi
    
    # Generate hash
    if ! PASSWORD_HASH=$(cargo run --example hash_password -- "$ADMIN_PASSWORD" 2>/tmp/rama-hash.log | tail -1); then
        log_error "Failed to generate password hash"
        log_info "Check log: /tmp/rama-hash.log"
        exit 1
    fi

    if [[ -z "$PASSWORD_HASH" || "$PASSWORD_HASH" != \$argon2* ]]; then
        log_error "Generated password hash is invalid"
        log_info "Check log: /tmp/rama-hash.log"
        exit 1
    fi
    
    log_success "Password hash generated"
}

##############################################################################
# Generate JWT Secret
##############################################################################

generate_jwt_secret() {
    log_info "Generating JWT secret..."
    
    JWT_SECRET=$(openssl rand -base64 48 | tr -d "=+/" | cut -c1-64)
    
    log_success "JWT secret generated"
}

##############################################################################
# Setup Installation Directory
##############################################################################

setup_install_dir() {
    log_info "Setting up installation directory: $INSTALL_DIR"
    
    # Create directories
    mkdir -p "$INSTALL_DIR"/{bin,config,certs,logs,data}
    
    # Copy binary
    cp "$SCRIPT_DIR/target/release/rama-elite-proxy" "$INSTALL_DIR/bin/"
    chmod +x "$INSTALL_DIR/bin/rama-elite-proxy"
    
    # Copy templates
    cp -r "$SCRIPT_DIR/templates" "$INSTALL_DIR/"
    
    # Set permissions
    chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    log_success "Installation directory configured"
}

##############################################################################
# Generate Self-Signed Certificate
##############################################################################

generate_certificates() {
    log_info "SSL Certificate configuration..."
    echo ""
    local cert_choice="1"
    local DOMAIN_NAME=""
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo -e "${BLUE}Your server IP: ${YELLOW}${SERVER_IP}${NC}"
    echo ""
    if [ "$AUTO_MODE" -eq 1 ]; then
        if [ -n "$AUTO_DOMAIN" ]; then
            cert_choice="2"
            DOMAIN_NAME="$AUTO_DOMAIN"
            log_info "Auto mode: using domain certificate for ${DOMAIN_NAME}"
        else
            cert_choice="1"
            log_info "Auto mode: using IP self-signed certificate"
        fi
    else
        echo -e "${YELLOW}SSL Certificate Options:${NC}"
        echo "  1) Self-signed for IP address (no domain yet)"
        echo "  2) Self-signed for domain name (you have a domain)"
        echo ""
        echo -e "${GREEN}Note:${NC} You can enable Let's Encrypt (ACME) later in config.yaml"
        echo ""
        read -p "Enter choice [1-2]: " cert_choice
    fi
    
    cd "$INSTALL_DIR/certs"
    
    case "$cert_choice" in
        2)
            # Domain certificate
            if [ -z "$DOMAIN_NAME" ]; then
                echo ""
                read -p "Enter your domain (e.g., proxy.example.com): " DOMAIN_NAME
            fi
            
            if [ -z "$DOMAIN_NAME" ]; then
                log_error "Domain name cannot be empty"
                DOMAIN_NAME="localhost"
            fi
            
            log_info "Generating certificate for domain: ${DOMAIN_NAME}"
            
            # Create certificate with SAN for domain
            cat > cert.conf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
CN=${DOMAIN_NAME}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN_NAME}
DNS.2 = *.${DOMAIN_NAME}
DNS.3 = localhost
IP.1 = ${SERVER_IP}
IP.2 = 127.0.0.1
EOF
            
            openssl req -x509 -newkey rsa:4096 -nodes \
                -keyout key.pem \
                -out cert.pem \
                -days 365 \
                -config cert.conf \
                -extensions v3_req
            
            rm cert.conf
            ;;
        *)
            # IP certificate (default)
            log_info "Generating certificate for IP: ${SERVER_IP}"
            
            # Create certificate with SAN for IP
            cat > cert.conf << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = v3_req

[dn]
C=US
ST=State
L=City
O=Organization
CN=${SERVER_IP}

[v3_req]
subjectAltName = @alt_names

[alt_names]
IP.1 = ${SERVER_IP}
IP.2 = 127.0.0.1
DNS.1 = localhost
EOF
            
            openssl req -x509 -newkey rsa:4096 -nodes \
                -keyout key.pem \
                -out cert.pem \
                -days 365 \
                -config cert.conf \
                -extensions v3_req
            
            rm cert.conf
            ;;
    esac
    
    # Set permissions
    chown "$SERVICE_USER":"$SERVICE_USER" *.pem
    chmod 600 key.pem
    chmod 644 cert.pem
    
    log_success "SSL certificates generated (valid for 365 days)"
    echo ""
    log_info "Certificate includes:"
    log_info "  - Server IP: ${SERVER_IP}"
    log_info "  - Localhost (127.0.0.1)"
    [ ! -z "$DOMAIN_NAME" ] && log_info "  - Domain: ${DOMAIN_NAME}"
}

##############################################################################
# Create Configuration File
##############################################################################

create_config() {
    log_info "Creating configuration file..."
    
    cat > "$INSTALL_DIR/config/config.yaml" << EOF
# Elite Rama Proxy - Production Configuration
# Auto-generated on $(date)

server:
  listen_addr: "0.0.0.0:8443"
  admin_path: "/admin_elite"
  fake_website_enabled: true
  fake_website_type: "construction"
  
  tls:
    enabled: true
    mode: "selfsigned"
    cert_file: "${INSTALL_DIR}/certs/cert.pem"
    key_file: "${INSTALL_DIR}/certs/key.pem"
    cert_dir: "${INSTALL_DIR}/certs/domains"
    selfsigned_hosts: ["localhost", "127.0.0.1", "*.local"]
    
    autocert:
      enabled: false
      domains: []
      email: ""
      cache_dir: "${INSTALL_DIR}/data/acme-cache"
    
    ja3_spoofing:
      enabled: true
      profile: "random"
      custom_ja3: ""
    
    ja4_spoofing:
      enabled: true
      profile: "chrome_120"
  
  timeouts:
    read: 30
    write: 30
    idle: 120
    shutdown: 30

proxy:
  transport:
    max_idle_conns: 2000
    max_idle_conns_per_host: 100
    idle_conn_timeout: 90
    tls_handshake_timeout: 10
    expect_continue_timeout: 1
    response_header_timeout: 30
    dial_timeout: 10
    keep_alive: 30
  
  profiles:
    enabled: true
    rotation: "random"
    browsers:
      - "chrome_131"
      - "firefox_133"
      - "safari_18"
      - "edge_120"
  
  streaming:
    flush_interval: 1
    buffer_size: 131072
    chunk_size: 32768
  
  http2:
    enabled: true
    akamai_fingerprint: true
    settings:
      header_table_size: 65536
      max_concurrent_streams: 1000
      initial_window_size: 6291456
      max_frame_size: 16384
      max_header_list_size: 262144
  
  tcp_fingerprint:
    enabled: true
    window_size: 65535
    ttl: 64
    mss: 1460
    window_scale: 8
    timestamp: true
    sack_permitted: true

stealth:
  behavioral_mimicry:
    enabled: true
    human_pattern: true
    min_delay_ms: 50
    max_delay_ms: 500
    burst_threshold: 5
    burst_delay_ms: 2000
  
  user_agents:
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    - "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
    - "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15"
  
  remove_headers:
    - "X-Forwarded-For"
    - "X-Forwarded-Host"
    - "X-Forwarded-Proto"
    - "X-Real-IP"
    - "Via"
    - "Forwarded"
    - "X-Forwarded-Port"
    - "X-Forwarded-Server"
    - "X-Original-Forwarded-For"
    - "CF-Connecting-IP"
    - "True-Client-IP"
  
  header_order:
    preserve: true
    chrome_order: true

rate_limit:
  enabled: true
  per_ip: 100
  per_domain: 1000
  burst: 20
  cleanup_interval: 300

circuit_breaker:
  enabled: true
  max_requests: 5
  timeout: 60
  interval: 10
  failure_threshold: 0.6

auth:
  jwt_secret: "${JWT_SECRET}"
  token_expiry: 86400
  refresh_enabled: true
  refresh_expiry: 604800
  default_user: "admin"
  default_password: "${PASSWORD_HASH}"

storage:
  type: "sled"
  path: "${INSTALL_DIR}/data/elite.db"
  cache_capacity: 1024

monitoring:
  prometheus:
    enabled: true
    path: "/metrics"
    auth_required: true
  
  tracing:
    enabled: true
    level: "info"
    format: "json"
    file: "${INSTALL_DIR}/logs/proxy.log"
    anonymize_ips: true

domains: {}
EOF
    
    chown "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR/config/config.yaml"
    chmod 600 "$INSTALL_DIR/config/config.yaml"
    
    log_success "Configuration file created"
}

##############################################################################
# Create Systemd Service
##############################################################################

create_systemd_service() {
    log_info "Creating systemd service..."
    
    cat > /etc/systemd/system/rama-proxy.service << EOF
[Unit]
Description=Elite Rama Proxy
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/bin/rama-elite-proxy --config $INSTALL_DIR/config/config.yaml
Restart=always
RestartSec=10
StandardOutput=append:$INSTALL_DIR/logs/stdout.log
StandardError=append:$INSTALL_DIR/logs/stderr.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/logs $INSTALL_DIR/data $INSTALL_DIR/certs/domains
ReadWritePaths=$INSTALL_DIR/certs

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    
    log_success "Systemd service created"
}

##############################################################################
# Configure Firewall
##############################################################################

configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        ufw allow 8443/tcp comment "Rama Proxy HTTPS"
        log_success "UFW firewall configured"
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=8443/tcp
        firewall-cmd --reload
        log_success "Firewalld configured"
    else
        log_warn "No firewall detected (ufw/firewalld)"
    fi
}

##############################################################################
# Start Service
##############################################################################

start_service() {
    log_info "Starting Rama Proxy service..."
    
    systemctl enable rama-proxy
    systemctl start rama-proxy
    
    # Wait for service to start
    sleep 3
    
    if systemctl is-active --quiet rama-proxy; then
        log_success "Service started successfully"
    else
        log_error "Service failed to start"
        log_info "Check logs: journalctl -u rama-proxy -n 50"
        exit 1
    fi
}

##############################################################################
# Test Installation
##############################################################################

test_installation() {
    log_info "Testing installation..."
    
    # Test 1: Service is running
    if ! systemctl is-active --quiet rama-proxy; then
        log_error "Service is not running"
        return 1
    fi
    log_success "✓ Service is running"
    
    # Test 2: Port is listening
    sleep 2
    if ! netstat -tuln 2>/dev/null | grep -q ":8443" && ! ss -tuln 2>/dev/null | grep -q ":8443"; then
        log_error "Port 8443 is not listening"
        return 1
    fi
    log_success "✓ Port 8443 is listening"
    
    # Test 3: Fake website responds
    sleep 2
    if curl -k -s https://localhost:8443/ | grep -q "Coming Soon"; then
        log_success "✓ Fake website is working"
    else
        log_warn "⚠ Fake website test inconclusive"
    fi
    
    # Test 4: Admin login page
    if curl -k -s https://localhost:8443/admin_elite/login | grep -q "login"; then
        log_success "✓ Admin login page accessible"
    else
        log_warn "⚠ Admin login page test inconclusive"
    fi
    
    log_success "Installation tests completed"
}

##############################################################################
# Save Credentials
##############################################################################

save_credentials() {
    local cred_file="$INSTALL_DIR/CREDENTIALS.txt"
    
    cat > "$cred_file" << EOF
╔════════════════════════════════════════════════════════════════╗
║                 ELITE RAMA PROXY - CREDENTIALS                 ║
╚════════════════════════════════════════════════════════════════╝

Installation Date: $(date)
Server IP: $(hostname -I | awk '{print $1}')

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ADMIN ACCESS:

  URL: https://$(hostname -I | awk '{print $1}'):8443/admin_elite/login
  
  Username: admin
  Password: ${ADMIN_PASSWORD}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

CONFIGURATION:

  Config File: ${INSTALL_DIR}/config/config.yaml
  Certificates: ${INSTALL_DIR}/certs/
  Logs: ${INSTALL_DIR}/logs/

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SERVICE MANAGEMENT:

  Status:  systemctl status rama-proxy
  Start:   systemctl start rama-proxy
  Stop:    systemctl stop rama-proxy
  Restart: systemctl restart rama-proxy
  Logs:    journalctl -u rama-proxy -f

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  IMPORTANT: Save this file in a secure location!
    Delete this file after saving credentials elsewhere.

╚════════════════════════════════════════════════════════════════╝
EOF
    
    chmod 600 "$cred_file"
    
    log_success "Credentials saved to: $cred_file"
}

##############################################################################
# Print Summary
##############################################################################

print_summary() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║       🎉  ELITE RAMA PROXY INSTALLED SUCCESSFULLY!  🎉           ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    echo -e "${GREEN}Installation Summary:${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "  📁 Installation Directory: ${BLUE}${INSTALL_DIR}${NC}"
    echo -e "  🔐 Admin Username: ${YELLOW}admin${NC}"
    echo -e "  🔑 Admin Password: ${YELLOW}${ADMIN_PASSWORD}${NC}"
    echo ""
    echo -e "  🌐 Admin Panel: ${GREEN}https://$(hostname -I | awk '{print $1}'):8443/admin_elite/login${NC}"
    echo -e "  🎭 Fake Website: ${GREEN}https://$(hostname -I | awk '{print $1}'):8443/${NC}"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
    echo "  1. Save your admin password: ${ADMIN_PASSWORD}"
    echo "  2. Full credentials saved in: ${INSTALL_DIR}/CREDENTIALS.txt"
    echo "  3. Service is running: systemctl status rama-proxy"
    echo "  4. View logs: journalctl -u rama-proxy -f"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${GREEN}Service Information:${NC}"
    echo "  ✅ Service enabled: Auto-starts on server boot"
    echo "  ✅ Auto-restart: Service restarts if it crashes"
    echo "  ✅ Restart policy: 10 second delay between restarts"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo -e "${GREEN}Next Steps:${NC}"
    echo "  • Access admin panel and add your first proxy domain"
    echo "  • Configure firewall to allow port 8443"
    echo "  • Setup DNS A records pointing to this server"
    echo "  • (Optional) Enable ACME for automatic SSL certificates"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
}

##############################################################################
# Setup Log Rotation
##############################################################################

setup_log_rotation() {
    cat > /etc/logrotate.d/rama-proxy << EOF
${INSTALL_DIR}/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 ${SERVICE_USER} ${SERVICE_USER}
    postrotate
        systemctl reload rama-proxy > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log_success "Log rotation configured (14 days, compressed)"
}

##############################################################################
# Main Installation Flow
##############################################################################

main() {
    echo ""
    echo -e "${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║            ELITE RAMA PROXY — AUTO INSTALLER 2026                ║"
    echo "║                  Production VPS Installation                      ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    check_root
    check_existing_installation
    
    # Show what will happen
    echo -e "  This installer will:"
    echo -e "    1. Install system packages (curl, git, gcc)"
    echo -e "    2. Install Rust compiler"
    echo -e "    3. Compile the proxy from source ${YELLOW}(~5-15 min)${NC}"
    echo -e "    4. Set up admin password + SSL certificates"
    echo -e "    5. Create a systemd service (auto-start on boot)"
    echo ""
    echo -e "  ${BOLD}Install location:${NC} ${INSTALL_DIR}"
    echo -e "  ${BOLD}Service port:${NC}     8443 (HTTPS)"
    echo ""
    
    if [ "$AUTO_MODE" -eq 1 ]; then
        log_info "Auto mode enabled: proceeding without interactive confirmation"
    else
        read -p "  Continue with installation? [Y/n] " confirm
        case "${confirm:-Y}" in
            [Nn]*)
                echo "Installation cancelled."
                exit 0
                ;;
        esac
    fi
    
    step "Detecting system"
    detect_os
    preflight_checks
    
    step "Installing system dependencies"
    install_dependencies
    
    step "Installing Rust"
    install_rust
    
    step "Creating service user"
    create_service_user
    
    step "Compiling proxy"
    compile_project
    
    step "Setting admin password"
    generate_admin_password
    
    step "Generating password hash"
    generate_password_hash
    
    step "Generating JWT secret"
    generate_jwt_secret
    
    step "Setting up installation directory"
    setup_install_dir
    
    step "Generating SSL certificates"
    generate_certificates
    
    step "Creating configuration"
    create_config
    
    step "Creating systemd service"
    create_systemd_service
    setup_log_rotation
    
    step "Configuring firewall"
    configure_firewall
    
    step "Starting service"
    start_service
    
    step "Testing installation"
    test_installation
    save_credentials
    
    # Summary
    print_summary
}

##############################################################################
# Parse Arguments & Run
##############################################################################

while [ $# -gt 0 ]; do
    case "$1" in
        --help|-h)
            show_help
            ;;
        --uninstall)
            check_root_simple
            uninstall
            ;;
        --auto)
            AUTO_MODE=1
            shift
            ;;
        --force)
            FORCE_REINSTALL=1
            shift
            ;;
        --domain)
            if [ -z "${2:-}" ]; then
                log_error "--domain requires a value"
                exit 1
            fi
            AUTO_DOMAIN="$2"
            shift 2
            ;;
        --admin-password)
            if [ -z "${2:-}" ]; then
                log_error "--admin-password requires a value"
                exit 1
            fi
            AUTO_ADMIN_PASSWORD="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            show_help
            exit 1
            ;;
    esac
done

main
