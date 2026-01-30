#!/bin/bash

##############################################################################
# Elite Rama Proxy - Auto Installer 2026
# 100% Automated Installation for Production VPS
##############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/rama-proxy"
SERVICE_USER="rama-proxy"
ADMIN_PASSWORD=""

##############################################################################
# Helper Functions
##############################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Safe sed replacement (works on all systems)
safe_sed() {
    local pattern="$1"
    local replacement="$2"
    local file="$3"
    
    # Try GNU sed first
    if sed --version >/dev/null 2>&1; then
        sed -i "s|${pattern}|${replacement}|g" "$file"
    else
        # macOS/BSD sed
        sed -i '' "s|${pattern}|${replacement}|g" "$file"
    fi
}

##############################################################################
# System Detection
##############################################################################

detect_os() {
    log_info "Detecting operating system..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        OS="unknown"
    fi
    
    log_success "Detected OS: $OS $OS_VERSION"
}

##############################################################################
# Check Root
##############################################################################

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "This script must be run as root"
        log_info "Please run: sudo bash install.sh"
        exit 1
    fi
}

##############################################################################
# Install Dependencies
##############################################################################

install_dependencies() {
    log_info "Installing system dependencies..."
    
    case "$OS" in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                curl \
                wget \
                git \
                build-essential \
                pkg-config \
                libssl-dev \
                ca-certificates \
                gnupg \
                lsb-release
            ;;
        centos|rhel|rocky|almalinux)
            yum install -y \
                curl \
                wget \
                git \
                gcc \
                gcc-c++ \
                make \
                openssl-devel \
                pkg-config \
                ca-certificates
            ;;
        *)
            log_error "Unsupported OS: $OS"
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
    
    if command -v rustc &> /dev/null; then
        log_warn "Rust already installed: $(rustc --version)"
        return
    fi
    
    # Install Rust for root (will be used to compile)
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    
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
    log_info "Compiling Rama Proxy (this may take a few minutes)..."
    
    cd "$SCRIPT_DIR"
    
    # Source Rust environment
    source "$HOME/.cargo/env"
    
    # Build release version
    cargo build --release
    
    if [ ! -f "target/release/rama-elite-proxy" ]; then
        log_error "Compilation failed - binary not found"
        exit 1
    fi
    
    log_success "Compilation completed successfully"
}

##############################################################################
# Generate Admin Password
##############################################################################

generate_admin_password() {
    log_info "Admin password configuration..."
    echo ""
    
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
    
    # Source Rust environment
    source "$HOME/.cargo/env"
    
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
    PASSWORD_HASH=$(cargo run --example hash_password "$ADMIN_PASSWORD" 2>/dev/null | tail -1)
    
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
    
    # Get server IP
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo -e "${BLUE}Your server IP: ${YELLOW}${SERVER_IP}${NC}"
    echo ""
    echo -e "${YELLOW}SSL Certificate Options:${NC}"
    echo "  1) Self-signed for IP address (no domain yet)"
    echo "  2) Self-signed for domain name (you have a domain)"
    echo ""
    echo -e "${GREEN}Note:${NC} You can enable Let's Encrypt (ACME) later in config.yaml"
    echo ""
    read -p "Enter choice [1-2]: " cert_choice
    
    cd "$INSTALL_DIR/certs"
    
    case "$cert_choice" in
        2)
            # Domain certificate
            echo ""
            read -p "Enter your domain (e.g., proxy.example.com): " DOMAIN_NAME
            
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
      email: "admin@example.com"
      cache_dir: "${INSTALL_DIR}/data/acme-cache"
      staging: false
    
    ja3_spoofing:
      enabled: true
      target_fingerprint: "chrome_latest"
  
  timeouts:
    read: 30
    write: 30
    idle: 120

auth:
  jwt_secret: "${JWT_SECRET}"
  token_expiry: 86400
  default_user: "admin"
  default_password: "${PASSWORD_HASH}"

proxy:
  max_connections: 10000
  buffer_size: 8192
  keep_alive: true
  
  rate_limit:
    enabled: true
    requests_per_minute: 100
    burst: 20
  
  circuit_breaker:
    enabled: true
    failure_threshold: 5
    timeout: 30
    half_open_requests: 3
  
  behavioral_mimicry:
    enabled: true
    base_delay_ms: 10
    jitter_ms: 5

stealth:
  path_sanitization: true
  header_order_preservation: true
  http2_fingerprint_mimicry: true
  websocket_detection: true

metrics:
  enabled: true
  prometheus_endpoint: "/metrics"

logging:
  level: "info"
  format: "json"
  output: "${INSTALL_DIR}/logs/proxy.log"
  max_size_mb: 100
  max_backups: 10
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
ExecStart=$INSTALL_DIR/bin/rama-elite-proxy
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
# Main Installation Flow
##############################################################################

main() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║            ELITE RAMA PROXY - AUTO INSTALLER 2026                ║"
    echo "║                  Production VPS Installation                      ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo ""
    
    log_info "Starting installation process..."
    echo ""
    
    # Pre-flight checks
    check_root
    detect_os
    
    # Installation steps
    install_dependencies
    install_rust
    create_service_user
    compile_project
    generate_admin_password
    generate_password_hash
    generate_jwt_secret
    setup_install_dir
    generate_certificates
    create_config
    create_systemd_service
    configure_firewall
    start_service
    
    # Post-installation
    test_installation
    save_credentials
    
    # Summary
    print_summary
    
    log_success "Installation completed successfully!"
}

##############################################################################
# Run Main
##############################################################################

main "$@"
