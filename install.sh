#!/bin/bash
set -e

# ═══════════════════════════════════════════════════════════════
# STUN Max — One-Click Server Deployment
# ═══════════════════════════════════════════════════════════════
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/uk0/stun_max/main/install.sh | bash
#
# Options (env vars):
#   STUN_MAX_PASSWORD=xxx    Set dashboard password (default: auto-generated)
#   STUN_MAX_PORT=8080       Signal server port (default: 8080)
#   STUN_MAX_STUN_PORT=3478  STUN server port (default: 3478)
#   STUN_MAX_VERSION=latest  Release version tag (default: latest)
# ═══════════════════════════════════════════════════════════════

REPO="uk0/stun_max"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/opt/stun_max"
WEB_DIR="${DATA_DIR}/web"
DB_FILE="${DATA_DIR}/stun_max.db"
LOG_DIR="/var/log"
TMP_DIR=$(mktemp -d)

PORT="${STUN_MAX_PORT:-8080}"
STUN_PORT="${STUN_MAX_STUN_PORT:-3478}"
STUN_HTTP_PORT="$((STUN_PORT + 1))"
VERSION="${STUN_MAX_VERSION:-latest}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $1"; }
ok()    { echo -e "${GREEN}[ OK ]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[FAIL]${NC} $1"; rm -rf "$TMP_DIR"; exit 1; }

cleanup() { rm -rf "$TMP_DIR"; }
trap cleanup EXIT

# ─── Banner ───────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║${NC}  ${BOLD}⚡ STUN Max — Server Deployment${NC}             ${BOLD}${CYAN}║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ─── Pre-flight ───────────────────────────────────────────────

[ "$(id -u)" -ne 0 ] && error "Please run as root: sudo bash install.sh"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) error "Unsupported architecture: $ARCH" ;;
esac

info "Platform: linux/${ARCH}"

for cmd in curl unzip systemctl; do
    command -v $cmd &>/dev/null || error "Required: $cmd (install with: apt install $cmd)"
done

# ─── Get latest release version ───────────────────────────────

if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release from GitHub..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -z "$VERSION" ] && error "No release found. Create a tag first: git tag v2.0.0 && git push origin v2.0.0"
fi

ok "Release: ${VERSION}"

# ─── Stop existing services ───────────────────────────────────

info "Stopping existing services..."
systemctl stop stun-max 2>/dev/null || true
systemctl stop stun-max-stun 2>/dev/null || true
fuser -k ${PORT}/tcp 2>/dev/null || true
fuser -k ${STUN_PORT}/udp 2>/dev/null || true
sleep 1

# ─── Download server zip ─────────────────────────────────────

RELEASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
ZIP_NAME="stun-max-server-${VERSION}-linux-${ARCH}.zip"
ZIP_URL="${RELEASE_URL}/${ZIP_NAME}"

info "Downloading ${ZIP_NAME}..."
if curl -fsSL -o "${TMP_DIR}/${ZIP_NAME}" "$ZIP_URL" 2>/dev/null; then
    ok "Downloaded server package"

    info "Extracting..."
    cd "$TMP_DIR" && unzip -qo "$ZIP_NAME"
    EXTRACT_DIR=$(ls -d stun-max-server-*/ 2>/dev/null | head -1)
    [ -z "$EXTRACT_DIR" ] && error "Extraction failed"
    ok "Extracted"

    mkdir -p "$DATA_DIR" "$WEB_DIR"
    cp "${EXTRACT_DIR}stun_max-server" "${INSTALL_DIR}/stun_max-server"
    cp "${EXTRACT_DIR}stun_max-stunserver" "${INSTALL_DIR}/stun_max-stunserver" 2>/dev/null || true
    [ -d "${EXTRACT_DIR}web" ] && cp -r "${EXTRACT_DIR}web/"* "$WEB_DIR/"
    [ -f "${EXTRACT_DIR}ip2region.xdb" ] && cp "${EXTRACT_DIR}ip2region.xdb" "$DATA_DIR/"
    chmod +x "${INSTALL_DIR}/stun_max-server" "${INSTALL_DIR}/stun_max-stunserver" 2>/dev/null
else
    warn "Zip not found, downloading individual binaries..."
    mkdir -p "$DATA_DIR" "$WEB_DIR"

    curl -fsSL -o "${INSTALL_DIR}/stun_max-server" "${RELEASE_URL}/stun_max-server-linux-${ARCH}" || \
        error "Failed to download server binary"
    chmod +x "${INSTALL_DIR}/stun_max-server"

    curl -fsSL -o "${INSTALL_DIR}/stun_max-stunserver" "${RELEASE_URL}/stun_max-stunserver-linux-${ARCH}" 2>/dev/null && \
        chmod +x "${INSTALL_DIR}/stun_max-stunserver" || true

    for f in index.html dashboard.js style.css; do
        curl -fsSL -o "${WEB_DIR}/${f}" "https://raw.githubusercontent.com/${REPO}/${VERSION}/web/${f}" 2>/dev/null || \
        curl -fsSL -o "${WEB_DIR}/${f}" "https://raw.githubusercontent.com/${REPO}/main/web/${f}" 2>/dev/null || true
    done

    curl -fsSL -o "${DATA_DIR}/ip2region.xdb" "${RELEASE_URL}/ip2region.xdb" 2>/dev/null || true
fi

ok "Binaries installed"

# ─── Generate password ────────────────────────────────────────

if [ -n "$STUN_MAX_PASSWORD" ]; then
    PASSWORD="$STUN_MAX_PASSWORD"
else
    PASSWORD=$(head -c 32 /dev/urandom | md5sum | head -c 32)
fi

# ─── Systemd services ────────────────────────────────────────

info "Creating systemd services..."

cat > /etc/systemd/system/stun-max.service << EOF
[Unit]
Description=STUN Max Signal Server
After=network-online.target stun-max-stun.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${DATA_DIR}
ExecStart=${INSTALL_DIR}/stun_max-server \\
    --addr :${PORT} \\
    --web-password ${PASSWORD} \\
    --web-dir ${WEB_DIR} \\
    --db ${DB_FILE} \\
    --ipdb ${DATA_DIR}/ip2region.xdb \\
    --stun-http http://127.0.0.1:${STUN_HTTP_PORT}
Restart=always
RestartSec=3
LimitNOFILE=65536
StandardOutput=append:${LOG_DIR}/stun_max.log
StandardError=append:${LOG_DIR}/stun_max.log

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/stun-max-stun.service << EOF
[Unit]
Description=STUN Max STUN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/stun_max-stunserver \\
    --addr :${STUN_PORT} \\
    --http :${STUN_HTTP_PORT}
Restart=always
RestartSec=3
StandardOutput=append:${LOG_DIR}/stun_max_stun.log
StandardError=append:${LOG_DIR}/stun_max_stun.log

[Install]
WantedBy=multi-user.target
EOF

# ─── Start services ───────────────────────────────────────────

info "Starting services..."
systemctl daemon-reload
systemctl enable --now stun-max-stun 2>/dev/null
sleep 1
systemctl enable --now stun-max

sleep 2
systemctl is-active --quiet stun-max && ok "Signal server running" || error "Server failed — run: journalctl -u stun-max -n 20"
systemctl is-active --quiet stun-max-stun && ok "STUN server running" || warn "STUN server not started"

# ─── Firewall detection ──────────────────────────────────────

FIREWALL_MANAGED=false
FIREWALL_TIPS=""

# Detect third-party control panels
if [ -f /www/server/panel/class/panelPlugin.py ] || command -v bt &>/dev/null; then
    FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[BT Panel / 宝塔面板]${NC} 安全 → 防火墙 → 添加规则:"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    TCP ${PORT}  (Signal Server / Dashboard)"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    UDP ${STUN_PORT}  (STUN Server)"
    FIREWALL_MANAGED=true
fi

if [ -d /opt/1panel ] || command -v 1pctl &>/dev/null; then
    FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[1Panel]${NC} 主机 → 防火墙 → 添加规则:"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    TCP ${PORT}  (Signal Server / Dashboard)"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    UDP ${STUN_PORT}  (STUN Server)"
    FIREWALL_MANAGED=true
fi

if [ -d /usr/local/hestia ] || command -v v-list-sys-config &>/dev/null; then
    FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[HestiaCP]${NC} Server → Firewall → Add Rule:"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    TCP ${PORT}  (Signal Server)"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    UDP ${STUN_PORT}  (STUN Server)"
    FIREWALL_MANAGED=true
fi

if [ -d /www/server/panel ] && [ ! -f /www/server/panel/class/panelPlugin.py ]; then
    # aaPanel (English version of BT)
    FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[aaPanel]${NC} Security → Firewall → Add Rule:"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    TCP ${PORT}  (Signal Server / Dashboard)"
    FIREWALL_TIPS="${FIREWALL_TIPS}\n    UDP ${STUN_PORT}  (STUN Server)"
    FIREWALL_MANAGED=true
fi

# System firewalls
if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
    info "Configuring UFW..."
    ufw allow ${PORT}/tcp comment "STUN Max Signal" 2>/dev/null
    ufw allow ${STUN_PORT}/udp comment "STUN Max STUN" 2>/dev/null
    ok "UFW rules added"
    FIREWALL_MANAGED=true
elif command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
    info "Configuring firewalld..."
    firewall-cmd --permanent --add-port=${PORT}/tcp 2>/dev/null
    firewall-cmd --permanent --add-port=${STUN_PORT}/udp 2>/dev/null
    firewall-cmd --reload 2>/dev/null
    ok "firewalld rules added"
    FIREWALL_MANAGED=true
elif command -v iptables &>/dev/null; then
    # Check if iptables has DROP rules that might block
    if iptables -L INPUT -n 2>/dev/null | grep -q "DROP\|REJECT"; then
        FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[iptables]${NC} Detected DROP/REJECT rules. Add:"
        FIREWALL_TIPS="${FIREWALL_TIPS}\n    iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT"
        FIREWALL_TIPS="${FIREWALL_TIPS}\n    iptables -I INPUT -p udp --dport ${STUN_PORT} -j ACCEPT"
        FIREWALL_MANAGED=true
    fi
fi

# Cloud provider security groups
FIREWALL_TIPS="${FIREWALL_TIPS}\n"
FIREWALL_TIPS="${FIREWALL_TIPS}\n  ${YELLOW}[Cloud Security Group / 云安全组]${NC}"
FIREWALL_TIPS="${FIREWALL_TIPS}\n  If using Alibaba Cloud / Tencent Cloud / AWS / GCP:"
FIREWALL_TIPS="${FIREWALL_TIPS}\n  Open these ports in the cloud console security group:"

# ─── Detect server IP ─────────────────────────────────────────

SERVER_IP=$(curl -4 -fsSL --max-time 5 ifconfig.me 2>/dev/null || \
            curl -4 -fsSL --max-time 5 icanhazip.com 2>/dev/null || \
            curl -4 -fsSL --max-time 5 ip.sb 2>/dev/null || \
            hostname -I 2>/dev/null | awk '{print $1}' || \
            echo "YOUR_SERVER_IP")

# ─── Summary ──────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  ✓ STUN Max Deployed Successfully            ║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${BOLD}Dashboard${NC}     http://${SERVER_IP}:${PORT}"
echo -e "  ${BOLD}Password${NC}      ${YELLOW}${PASSWORD}${NC}"
echo -e "  ${BOLD}WebSocket${NC}     ws://${SERVER_IP}:${PORT}/ws"
echo -e "  ${BOLD}STUN Server${NC}   ${SERVER_IP}:${STUN_PORT} (UDP)"
echo -e "  ${BOLD}Version${NC}       ${VERSION}"
echo ""
echo -e "  ${BOLD}Connect:${NC}"
echo -e "  ${CYAN}./stun_max-cli --server ws://${SERVER_IP}:${PORT}/ws \\${NC}"
echo -e "  ${CYAN}    --room <room> --password <pass> --name <name>${NC}"
echo ""

# ─── Port requirements ────────────────────────────────────────

echo -e "  ${BOLD}${RED}Required Ports (must be open):${NC}"
echo -e "  ┌──────────┬──────────┬──────────────────────────────┐"
echo -e "  │ ${BOLD}Port${NC}     │ ${BOLD}Protocol${NC} │ ${BOLD}Purpose${NC}                        │"
echo -e "  ├──────────┼──────────┼──────────────────────────────┤"
echo -e "  │ ${CYAN}${PORT}${NC}      │ TCP      │ Signal Server + Dashboard    │"
echo -e "  │ ${CYAN}${STUN_PORT}${NC}      │ UDP      │ STUN Server (NAT traversal)  │"
echo -e "  └──────────┴──────────┴──────────────────────────────┘"
echo ""

if [ -n "$FIREWALL_TIPS" ]; then
    echo -e "  ${BOLD}Firewall Configuration:${NC}"
    echo -e "$FIREWALL_TIPS"
    echo ""
fi

echo -e "  ${BOLD}Manage:${NC}"
echo -e "  systemctl status stun-max        # status"
echo -e "  systemctl restart stun-max       # restart"
echo -e "  journalctl -u stun-max -f        # logs"
echo ""
echo -e "  ${BOLD}Uninstall:${NC}"
echo -e "  systemctl disable --now stun-max stun-max-stun"
echo -e "  rm /etc/systemd/system/stun-max*.service && systemctl daemon-reload"
echo -e "  rm ${INSTALL_DIR}/stun_max-* && rm -rf ${DATA_DIR}"
echo ""
