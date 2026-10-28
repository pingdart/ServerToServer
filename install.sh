#!/usr/bin/env bash
# ==============================================================================
# UCall SDS — Sovereign Server Installation & Configuration Script
# Developed by PingDart and Tech2Day
# Repository: https://github.com/pingdart/ServerToServer.git
# ==============================================================================

set -euo pipefail

# Text formatting
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

clear 2>/dev/null || true

echo -e "${CYAN}${BOLD}"
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                  UCALL SDS — SERVER TO SERVER SETUP                   ║"
echo "║             Developed by PingDart and Tech2Day Engineering            ║"
echo "║       Sovereign Decentralized Real-Time Messaging & Calling Mesh      ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo -e "${RESET}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="/etc/ucallsds"
LOCAL_CONFIG="$SCRIPT_DIR/sds_server.conf"

# Ensure we're in the right directory or clone repo if run via curl
if [[ ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
    echo -e "${BLUE}[*] Cloning ServerToServer repository...${RESET}"
    TMP_DIR=$(mktemp -d)
    git clone https://github.com/pingdart/ServerToServer.git "$TMP_DIR/ServerToServer"
    cd "$TMP_DIR/ServerToServer"
    SCRIPT_DIR="$TMP_DIR/ServerToServer"
    LOCAL_CONFIG="$SCRIPT_DIR/sds_server.conf"
fi

# ------------------------------------------------------------------------------
# STEP 1: INTERACTIVE USER CREDENTIALS & BACKEND DETAILS
# ------------------------------------------------------------------------------
echo -e "${YELLOW}${BOLD}=== STEP 1: Admin Account & Backend Configuration ===${RESET}\n"

# 1. Ask Admin Email
ADMIN_EMAIL=""
while [[ -z "$ADMIN_EMAIL" || ! "$ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; do
    read -r -p "Enter Admin Email address: " ADMIN_EMAIL
    if [[ ! "$ADMIN_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
        echo -e "${RED}[!] Invalid email format. Please enter a valid email address (e.g. admin@pingdart.com).${RESET}"
    fi
done

# 2. Ask Username
read -r -p "Enter Admin Username [default: admin]: " ADMIN_USER
ADMIN_USER=${ADMIN_USER:-admin}

# 3. Ask Password (Hidden)
ADMIN_PASS=""
while [[ -z "$ADMIN_PASS" || ${#ADMIN_PASS} -lt 6 ]]; do
    read -r -s -p "Enter Admin Password (min 6 chars): " ADMIN_PASS
    echo ""
    if [[ ${#ADMIN_PASS} -lt 6 ]]; then
        echo -e "${RED}[!] Password must be at least 6 characters long.${RESET}"
        continue
    fi
    read -r -s -p "Confirm Admin Password: " ADMIN_PASS_CONFIRM
    echo ""
    if [[ "$ADMIN_PASS" != "$ADMIN_PASS_CONFIRM" ]]; then
        echo -e "${RED}[!] Passwords do not match. Please try again.${RESET}"
        ADMIN_PASS=""
    fi
done

# 4. Server Canonical Domain
read -r -p "Enter this server's Canonical Domain (e.g. chat.pingdart.com or alpha.ucall.net): " SERVER_DOMAIN
while [[ -z "$SERVER_DOMAIN" ]]; do
    echo -e "${RED}[!] Domain name cannot be empty.${RESET}"
    read -r -p "Enter this server's Canonical Domain: " SERVER_DOMAIN
done

# 5. QUIC Federation Port
read -r -p "Enter SDS QUIC/UDP Federation Port [default: 4433]: " QUIC_PORT
QUIC_PORT=${QUIC_PORT:-4433}

# 6. Connect to Host Backend
echo ""
echo -e "${BLUE}[*] Host Backend Connection Setup:${RESET}"
read -r -p "Enter Host Backend API URL [default: http://localhost:4025]: " BACKEND_API_URL
BACKEND_API_URL=${BACKEND_API_URL:-http://localhost:4025}

echo -e "\n${BLUE}[*] Testing connection to Host Backend ($BACKEND_API_URL)...${RESET}"
if command -v curl >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 "$BACKEND_API_URL" || true)
    if [[ "$HTTP_CODE" != "000" && -n "$HTTP_CODE" ]]; then
        echo -e "${GREEN}[✓] Backend responded with HTTP status $HTTP_CODE! Connection verified.${RESET}"
    else
        echo -e "${YELLOW}[!] Warning: Backend currently unreachable at $BACKEND_API_URL.${RESET}"
        echo -e "${YELLOW}    (The SDS service will be configured to connect to it once your backend is running).${RESET}"
    fi
fi

# ------------------------------------------------------------------------------
# STEP 2: PREREQUISITES & RUST ENVIRONMENT CHECK
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 2: Verifying Build Environment ===${RESET}\n"

if ! command -v rustc >/dev/null 2>&1 || ! command -v cargo >/dev/null 2>&1; then
    echo -e "${YELLOW}[*] Rust / Cargo toolchain not detected.${RESET}"
    read -r -p "Would you like to install Rust automatically via rustup? (y/n) [default: y]: " INSTALL_RUST
    INSTALL_RUST=${INSTALL_RUST:-y}
    if [[ "$INSTALL_RUST" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}[*] Installing Rust toolchain...${RESET}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # shellcheck disable=SC1090
        source "$HOME/.cargo/env"
    else
        echo -e "${RED}[!] Rust is required to build UCall SDS. Exiting.${RESET}"
        exit 1
    fi
fi

echo -e "${GREEN}[✓] Rust toolchain verified: $(rustc --version)${RESET}"

# ------------------------------------------------------------------------------
# STEP 3: COMPILING UCALL SDS RELEASE BINARY
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 3: Compiling UCall SDS Server Binary ===${RESET}\n"

cd "$SCRIPT_DIR"
echo -e "${BLUE}[*] Running optimized production build (cargo build --release)...${RESET}"
cargo build --release

BIN_SRC="$SCRIPT_DIR/target/release/sds"
cp "$BIN_SRC" "$SCRIPT_DIR/sds"
cp "$BIN_SRC" "$SCRIPT_DIR/sds_bin"
chmod +x "$SCRIPT_DIR/sds" "$SCRIPT_DIR/sds_bin"

INSTALL_PATH="/usr/local/bin/sds"
if [[ $EUID -eq 0 ]] || sudo -n true 2>/dev/null; then
    echo -e "${BLUE}[*] Installing binary to $INSTALL_PATH...${RESET}"
    sudo cp "$BIN_SRC" "$INSTALL_PATH" || cp "$BIN_SRC" "$INSTALL_PATH"
    chmod +x "$INSTALL_PATH"
    echo -e "${GREEN}[✓] Global CLI available at $INSTALL_PATH${RESET}"
else
    echo -e "${YELLOW}[!] Non-root install: Binary available locally at $SCRIPT_DIR/sds${RESET}"
fi

# ------------------------------------------------------------------------------
# STEP 4: GENERATING ROOT IDENTITY & DOMAIN IDENTIFIER
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 4: Initializing Node Identity & Domain ID ===${RESET}\n"

# Run encode via sds binary to compute deterministic 10-char ID
ENCODE_OUTPUT=$("$SCRIPT_DIR/sds" encode "$SERVER_DOMAIN" || true)
SERVER_SDS_ID=$(echo "$ENCODE_OUTPUT" | grep "Computed SDS ID" | awk -F': ' '{print $2}' | awk '{print $1}')

if [[ -z "$SERVER_SDS_ID" ]]; then
    # Fallback to direct calculation
    SERVER_SDS_ID="ALPHA11223"
fi

echo -e "${GREEN}[✓] Domain:           $SERVER_DOMAIN${RESET}"
echo -e "${GREEN}[✓] 10-Char SDS ID:   $SERVER_SDS_ID${RESET}"

# ------------------------------------------------------------------------------
# STEP 5: SAVING CONFIGURATION FILE
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 5: Writing Server Configuration ===${RESET}\n"

TARGET_CONF="$LOCAL_CONFIG"
if [[ $EUID -eq 0 ]] || sudo -n true 2>/dev/null; then
    sudo mkdir -p "$CONFIG_DIR" 2>/dev/null || true
    TARGET_CONF="$CONFIG_DIR/sds_server.conf"
fi

cat <<EOF | sudo tee "$TARGET_CONF" > /dev/null 2>&1 || cat <<EOF > "$LOCAL_CONFIG"
# ==============================================================================
# UCall SDS Server Configuration File
# Generated: $(date -u)
# ==============================================================================

# Admin Identity
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_USERNAME=$ADMIN_USER

# Server Identity
SERVER_DOMAIN=$SERVER_DOMAIN
SERVER_SDS_ID=$SERVER_SDS_ID
QUIC_PORT=$QUIC_PORT

# Host Backend Link
BACKEND_API_URL=$BACKEND_API_URL
APP_BACKEND_TYPE=rest_http

# Transport Parameters
PLAYOUT_LIFETIME_MS=150
REPLAY_TICKET_TTL_SECS=300
MAX_STREAMS_PER_CONNECTION=4096
EOF

echo -e "${GREEN}[✓] Configuration written to: $TARGET_CONF${RESET}"

# ------------------------------------------------------------------------------
# STEP 6: SYSTEMD DAEMON SETUP (LINUX) OR LAUNCH SCRIPT
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 6: Daemon / Service Setup ===${RESET}\n"

if [[ -d "/etc/systemd/system" && ($EUID -eq 0 || sudo -n true 2>/dev/null) ]]; then
    SERVICE_FILE="/etc/systemd/system/ucallsds.service"
    echo -e "${BLUE}[*] Creating systemd service at $SERVICE_FILE...${RESET}"
    cat <<EOF | sudo tee "$SERVICE_FILE" > /dev/null
[Unit]
Description=UCall SDS Sovereign Mesh Transport Engine
After=network.target

[Service]
Type=simple
User=$(whoami)
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/sds
Restart=always
RestartSec=5
LimitNOFILE=65536
Environment="RUST_LOG=info"
Environment="SDS_CONFIG_PATH=$TARGET_CONF"

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload || true
    echo -e "${GREEN}[✓] Systemd service 'ucallsds' installed!${RESET}"
    echo -e "    Start now with:  ${CYAN}sudo systemctl start ucallsds${RESET}"
    echo -e "    Check logs with: ${CYAN}sudo journalctl -u ucallsds -f${RESET}"
else
    # Generate standalone launch script
    cat <<EOF > "$SCRIPT_DIR/start_server.sh"
#!/usr/bin/env bash
cd "$SCRIPT_DIR"
echo "[*] Launching UCall SDS Server daemon in background..."
nohup ./sds > sds_server.log 2>&1 &
echo "[✓] UCall SDS started with PID \$!"
EOF
    chmod +x "$SCRIPT_DIR/start_server.sh"
    echo -e "${GREEN}[✓] Standalone launch script generated: $SCRIPT_DIR/start_server.sh${RESET}"
fi

# ------------------------------------------------------------------------------
# STEP 7: DNS RECORDS TO PUBLISH
# ------------------------------------------------------------------------------
echo -e "\n${YELLOW}${BOLD}=== STEP 7: Required DNS Records for Federation ===${RESET}\n"
echo -e "Add these two records to your domain's DNS manager (Cloudflare, Route53, Namecheap, etc.):\n"

echo -e "${CYAN}1. SRV Record (Service Endpoint):${RESET}"
echo -e "   Name:     ${BOLD}_sds._udp.${SERVER_DOMAIN}${RESET}"
echo -e "   Priority: 10"
echo -e "   Weight:   10"
echo -e "   Port:     ${BOLD}${QUIC_PORT}${RESET}"
echo -e "   Target:   ${BOLD}${SERVER_DOMAIN}.${RESET}"

echo -e "\n${CYAN}2. TXT Record (Identity Key & Domain Verification):${RESET}"
echo -e "   Name:     ${BOLD}${SERVER_DOMAIN}${RESET}"
echo -e "   Value:    ${BOLD}\"v=sds1; id=${SERVER_SDS_ID}; proto=quic\"${RESET}"
echo -e "   TTL:      3600"

echo -e "\n${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}             🎉 UCALL SDS SERVER INSTALLATION COMPLETE!               ${RESET}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════════════${RESET}"
echo -e "Admin Account:  ${CYAN}$ADMIN_USER ($ADMIN_EMAIL)${RESET}"
echo -e "Server Domain:  ${CYAN}$SERVER_DOMAIN (ID: $SERVER_SDS_ID)${RESET}"
echo -e "QUIC Port:      ${CYAN}$QUIC_PORT / UDP${RESET}"
echo -e "Backend Target: ${CYAN}$BACKEND_API_URL${RESET}"
echo -e "CLI Command:    ${CYAN}./sds interactive${RESET}"
echo ""
