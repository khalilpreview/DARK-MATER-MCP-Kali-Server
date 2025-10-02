#!/bin/bash

#
# MCP Kali Server Installation Script
# 
# This script performs an idempotent installation of the MCP Kali Server
# with systemd service, user creation, and enrollment token generation.
#

set -euo pipefail

# Configuration
SCRIPT_NAME="$(basename "$0")"
INS# Check if systemd is available
check_systemd() {
    if [[ $(ps -p 1 -o comm= 2>/dev/null) == "systemd" ]]; then
        return 0  # systemd is available
    else
        return 1  # systemd is not available
    fi
}

# Create systemd service
create_service() {
    if check_systemd; then
        log_info "Creating systemd service..."
        
        cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOFDIR="/opt/mcp-kali-server"
CONFIG_DIR="/etc/mcp-kali"
DATA_DIR="/var/lib/mcp"
SERVICE_USER="mcpserver"
SERVICE_NAME="mcp-kali-server"
REPO_URL="https://github.com/khalilpreview/MCP-Kali-Server.git"
PYTHON_MIN_VERSION="3.10"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        log_info "Usage: sudo $SCRIPT_NAME"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check if we're on a Debian/Ubuntu system
    if ! command -v apt-get &> /dev/null; then
        log_error "This installer is designed for Debian/Ubuntu systems"
        exit 1
    fi
    
    # Check Python version
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
            log_error "Python ${PYTHON_MIN_VERSION}+ is required (found ${PYTHON_VERSION})"
            exit 1
        fi
        log_success "Python ${PYTHON_VERSION} found"
    else
        log_error "Python 3 is not installed"
        exit 1
    fi
    
    # Check for essential tools
    local missing_tools=()
    for tool in git curl systemctl; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install them with: apt-get update && apt-get install -y ${missing_tools[*]}"
        exit 1
    fi
    
    log_success "System requirements check passed"
}

# Install system dependencies
install_dependencies() {
    log_info "Installing system dependencies..."
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package list
    apt-get update -qq
    
    # Install required packages
    apt-get install -y \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        git \
        curl \
        nmap \
        sqlite3 \
        ca-certificates \
        python3-requests
    
    log_success "System dependencies installed"
}

# Create service user
create_user() {
    log_info "Creating service user: $SERVICE_USER"
    
    if id "$SERVICE_USER" &>/dev/null; then
        log_info "User $SERVICE_USER already exists"
    else
        useradd --system --home-dir "$INSTALL_DIR" --shell /bin/false --comment "MCP Kali Server" "$SERVICE_USER"
        log_success "Created user: $SERVICE_USER"
    fi
}

# Create directories
create_directories() {
    log_info "Creating directories..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    chmod 755 "$CONFIG_DIR"
    chown root:root "$CONFIG_DIR"
    
    # Create data directories
    mkdir -p "$DATA_DIR/artifacts"
    mkdir -p "$DATA_DIR/memory"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
    
    # Note: Install directory will be created during repository setup
    log_success "Directories created"
}

# Clone or update repository
setup_repository() {
    log_info "Setting up repository..."
    
    # Verify user exists
    if ! id "$SERVICE_USER" &>/dev/null; then
        log_error "Service user $SERVICE_USER does not exist"
        exit 1
    fi
    
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        log_info "Repository exists, updating..."
        cd "$INSTALL_DIR"
        sudo -u "$SERVICE_USER" git fetch origin
        sudo -u "$SERVICE_USER" git reset --hard origin/main
        log_success "Repository updated"
    else
        log_info "Cloning repository..."
        
        # Remove existing directory completely
        rm -rf "$INSTALL_DIR"
        
        # Create directory as root
        mkdir -p "$INSTALL_DIR"
        
        # Set ownership to service user
        chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
        
        # Clone as the service user into the owned directory
        if sudo -u "$SERVICE_USER" git clone "$REPO_URL" "$INSTALL_DIR"; then
            log_success "Repository cloned successfully"
        else
            log_error "Failed to clone repository from $REPO_URL"
            log_info "You may need to check your internet connection or repository access"
            exit 1
        fi
    fi
    
    # Make scripts executable
    chmod +x "$INSTALL_DIR/kali_server.py"
    chmod +x "$INSTALL_DIR/dark-mater_kali-mcp"
    
    # Create symlink for global access
    ln -sf "$INSTALL_DIR/dark-mater_kali-mcp" /usr/local/bin/dark-mater_kali-mcp
    
    log_success "CLI tool installed globally"
}

# Setup Python virtual environment
setup_venv() {
    log_info "Setting up Python virtual environment..."
    
    cd "$INSTALL_DIR"
    
    # Remove existing venv if it exists
    if [[ -d "venv" ]]; then
        log_info "Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Create new virtual environment
    sudo -u "$SERVICE_USER" python3 -m venv venv
    
    # Upgrade pip
    sudo -u "$SERVICE_USER" ./venv/bin/pip install --upgrade pip
    
    # Install requirements
    if [[ -f "requirements.txt" ]]; then
        sudo -u "$SERVICE_USER" ./venv/bin/pip install -r requirements.txt
        log_success "Python dependencies installed"
    else
        log_error "requirements.txt not found"
        exit 1
    fi
}

# Generate enrollment token
generate_enrollment_token() {
    log_info "Generating enrollment token..."
    
    # Generate unique server ID and token
    SERVER_ID=$(openssl rand -hex 8)
    ENROLLMENT_TOKEN=$(openssl rand -hex 16)
    CREATED_TIME=$(date -u +"%Y-%m-%dT%H:%M:%S.%6NZ")
    
    # Create enrollment file
    cat > "$CONFIG_DIR/enroll.json" <<EOF
{
  "id": "$SERVER_ID",
  "token": "$ENROLLMENT_TOKEN",
  "created": "$CREATED_TIME"
}
EOF
    
    # Secure the file
    chmod 600 "$CONFIG_DIR/enroll.json"
    chown root:root "$CONFIG_DIR/enroll.json"
    
    log_success "Enrollment token generated"
}

# Create default scope configuration
create_scope_config() {
    log_info "Creating default scope configuration..."
    
    if [[ ! -f "$CONFIG_DIR/scope.json" ]]; then
        cat > "$CONFIG_DIR/scope.json" <<EOF
{
  "allowed_cidrs": [
    "10.0.0.0/8",
    "192.168.0.0/16",
    "172.16.0.0/12"
  ],
  "allow_destructive": false
}
EOF
        chmod 644 "$CONFIG_DIR/scope.json"
        chown root:root "$CONFIG_DIR/scope.json"
        log_success "Default scope configuration created"
    else
        log_info "Scope configuration already exists"
    fi
}

# Create systemd service
create_service() {
    log_info "Creating systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=MCP Kali Server
Documentation=https://github.com/khalilpreview/MCP-Kali-Server
After=network.target
Wants=network.target

[Service]
Type=exec
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/kali_server.py --bind 0.0.0.0:5000
ExecReload=/bin/kill -HUP \$MAINPID
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="NGROK_AUTHTOKEN="
Restart=on-failure
RestartSec=5
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DATA_DIR $CONFIG_DIR
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Environment
Environment=PYTHONPATH=$INSTALL_DIR
Environment=MCP_CONFIG_DIR=$CONFIG_DIR
Environment=MCP_DATA_DIR=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
        
        # Reload systemd
        systemctl daemon-reload
        
        log_success "Systemd service created"
    else
        log_info "Systemd not detected (likely Docker/WSL/chroot environment)"
        log_info "Skipping systemd service creation"
        log_success "Manual startup methods will be provided"
    fi
}

# Enable and start service
start_service() {
    if check_systemd; then
        log_info "Enabling and starting service..."
        
        # Enable service to start on boot
        systemctl enable "$SERVICE_NAME"
        
        # Start the service
        systemctl start "$SERVICE_NAME"
        
        # Brief delay for service to start
        sleep 2
        
        # Check service status
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            log_success "Service started successfully"
            
            # Show service status
            systemctl --no-pager status "$SERVICE_NAME"
        else
            log_error "Failed to start service"
            log_info "Check service logs with: journalctl -u $SERVICE_NAME"
            exit 1
        fi
    else
        log_info "Systemd not available - service startup skipped"
        log_success "Server ready for manual startup"
    fi
}

# Display enrollment information
display_enrollment_info() {
    log_success "Installation completed successfully!"
    echo
    log_info "=== ENROLLMENT INFORMATION ==="
    echo
    log_info "Copy the following JSON to enroll this server:"
    echo
    cat "$CONFIG_DIR/enroll.json"
    echo
    if check_systemd; then
        log_info "=== SERVICE INFORMATION ==="
        echo  
        log_info "Service name: $SERVICE_NAME"
        log_info "Service status: systemctl status $SERVICE_NAME"
        log_info "Service logs: journalctl -u $SERVICE_NAME -f"
        log_info "Server URL: http://$(hostname -I | awk '{print $1}'):5000"
        echo
    else
        log_info "=== MANUAL STARTUP REQUIRED ==="
        echo
        log_info "Init system check: $(ps -p 1 -o comm= 2>/dev/null || echo 'unknown')"
        log_info "Systemd not available (Docker/WSL/chroot environment detected)"
        echo
        log_info "Start the server manually:"
        echo
        log_info "# Foreground mode:"
        log_info "$INSTALL_DIR/venv/bin/python $INSTALL_DIR/kali_server.py --bind 0.0.0.0:5000"
        echo
        log_info "# Background mode (with nohup):"
        log_info "nohup $INSTALL_DIR/venv/bin/python $INSTALL_DIR/kali_server.py --bind 0.0.0.0:5000 > /var/log/mcp-kali-server.log 2>&1 &"
        echo
        log_info "# With ngrok tunnel:"
        log_info "nohup $INSTALL_DIR/venv/bin/python $INSTALL_DIR/kali_server.py --bind 0.0.0.0:5000 --ngrok --ngrok-authtoken YOUR_TOKEN > /var/log/mcp-kali-server.log 2>&1 &"
        echo
        log_info "Server URL: http://$(hostname -I | awk '{print $1}'):5000"
        echo
    fi
    log_info "=== CONFIGURATION FILES ==="
    echo
    log_info "Enrollment token: $CONFIG_DIR/enroll.json"
    log_info "Scope configuration: $CONFIG_DIR/scope.json"
    log_info "Service configuration: /etc/systemd/system/$SERVICE_NAME.service"
    echo
    log_info "=== NEXT STEPS ==="
    echo
    log_info "1. Use the enrollment JSON above to register this server"
    log_info "2. Configure scope settings in $CONFIG_DIR/scope.json if needed"
    log_info "3. Test the server with: curl http://localhost:5000/status"
    echo
    log_info "=== NGROK SETUP (OPTIONAL) ==="
    echo
    log_info "For remote access via ngrok tunnel:"
    log_info "1. Get ngrok auth token from https://dashboard.ngrok.com/get-started/your-authtoken"
    log_info "2. Edit /etc/systemd/system/$SERVICE_NAME.service"
    log_info "3. Set Environment=\"NGROK_AUTHTOKEN=your_token_here\""
    log_info "4. Add --ngrok flag to ExecStart command"
    log_info "5. Run: systemctl daemon-reload && systemctl restart $SERVICE_NAME"
    log_info "6. Check tunnel URL in service logs: journalctl -u $SERVICE_NAME -f"
    echo
    log_info "=== CLI TOOL ==="
    echo
    log_info "Easy server management with:"
    log_info "sudo dark-mater_kali-mcp start-server"
    echo
    if ! check_systemd; then
        log_info "=== QUICK START ==="
        echo
        log_info "Since systemd is not available, start the server now:"
        log_info "sudo dark-mater_kali-mcp start-server"
        echo
        log_info "Or run directly:"
        log_info "$INSTALL_DIR/venv/bin/python $INSTALL_DIR/kali_server.py --bind 0.0.0.0:5000"
        echo
    fi
}

# Cleanup on failure
cleanup_on_failure() {
    log_error "Installation failed, cleaning up..."
    
    # Stop and disable service if it was created
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
    fi
    
    # Remove enrollment token if it was created
    rm -f "$CONFIG_DIR/enroll.json"
    
    log_info "Cleanup completed"
}

# Main installation function
main() {
    log_info "Starting MCP Kali Server installation..."
    
    # Set trap for cleanup on failure
    trap cleanup_on_failure ERR
    
    # Run installation steps
    check_root
    check_requirements
    install_dependencies
    create_user
    create_directories
    setup_repository
    setup_venv
    generate_enrollment_token
    create_scope_config
    create_service
    start_service
    display_enrollment_info
    
    # Remove trap
    trap - ERR
    
    log_success "Installation completed successfully!"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "MCP Kali Server Installation Script"
        echo
        echo "Usage: $SCRIPT_NAME [options]"
        echo
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --uninstall    Uninstall the server"
        echo
        echo "This script must be run as root."
        exit 0
        ;;
    --uninstall)
        log_info "Uninstalling MCP Kali Server..."
        
        # Stop and disable service
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        
        # Remove user
        if id "$SERVICE_USER" &>/dev/null; then
            userdel "$SERVICE_USER" 2>/dev/null || true
        fi
        
        # Remove directories
        rm -rf "$INSTALL_DIR"
        rm -rf "$DATA_DIR"
        
        log_info "Configuration files in $CONFIG_DIR have been left intact"
        log_info "Remove them manually if desired: rm -rf $CONFIG_DIR"
        
        log_success "Uninstallation completed"
        exit 0
        ;;
    "")
        # Run normal installation
        main
        ;;
    *)
        log_error "Unknown option: $1"
        log_info "Use --help for usage information"
        exit 1
        ;;
esac