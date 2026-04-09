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
    command -v $cmd &>/dev/null || error "Required: $cmd (install with apt/yum)"
done

# ─── Get latest release version ───────────────────────────────

if [ "$VERSION" = "latest" ]; then
    info "Fetching latest release from GitHub..."
    VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
    [ -z "$VERSION" ] && error "No release found at github.com/${REPO}/releases. Create a tag first: git tag v2.0.0 && git push origin v2.0.0"
fi

ok "Release: ${VERSION}"

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
    [ -z "$EXTRACT_DIR" ] && error "Extraction failed — zip structure unexpected"
    ok "Extracted to ${EXTRACT_DIR}"

    # Install from zip
    mkdir -p "$DATA_DIR" "$WEB_DIR"
    cp "${EXTRACT_DIR}stun_max-server" "${INSTALL_DIR}/stun_max-server"
    cp "${EXTRACT_DIR}stun_max-stunserver" "${INSTALL_DIR}/stun_max-stunserver" 2>/dev/null || true
    [ -d "${EXTRACT_DIR}web" ] && cp -r "${EXTRACT_DIR}web/"* "$WEB_DIR/"
    [ -f "${EXTRACT_DIR}ip2region.xdb" ] && cp "${EXTRACT_DIR}ip2region.xdb" "$DATA_DIR/"
    chmod +x "${INSTALL_DIR}/stun_max-server" "${INSTALL_DIR}/stun_max-stunserver" 2>/dev/null
else
    # Fallback: download individual binaries
    warn "Zip not found, downloading individual binaries..."
    mkdir -p "$DATA_DIR" "$WEB_DIR"

    info "Downloading stun_max-server..."
    curl -fsSL -o "${INSTALL_DIR}/stun_max-server" "${RELEASE_URL}/stun_max-server-linux-${ARCH}" || \
        error "Failed to download server binary"
    chmod +x "${INSTALL_DIR}/stun_max-server"

    info "Downloading stun_max-stunserver..."
    curl -fsSL -o "${INSTALL_DIR}/stun_max-stunserver" "${RELEASE_URL}/stun_max-stunserver-linux-${ARCH}" 2>/dev/null && \
        chmod +x "${INSTALL_DIR}/stun_max-stunserver" || warn "STUN server not available"

    info "Downloading web dashboard..."
    for f in index.html dashboard.js style.css; do
        curl -fsSL -o "${WEB_DIR}/${f}" "https://raw.githubusercontent.com/${REPO}/${VERSION}/web/${f}" 2>/dev/null || \
        curl -fsSL -o "${WEB_DIR}/${f}" "https://raw.githubusercontent.com/${REPO}/main/web/${f}" 2>/dev/null || true
    done

    info "Downloading ip2region database..."
    curl -fsSL -o "${DATA_DIR}/ip2region.xdb" "${RELEASE_URL}/ip2region.xdb" 2>/dev/null || \
        warn "IP geolocation database not available"
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
systemctl stop stun-max stun-max-stun 2>/dev/null || true
fuser -k ${PORT}/tcp 2>/dev/null || true
fuser -k ${STUN_PORT}/udp 2>/dev/null || true
sleep 1
systemctl enable --now stun-max-stun 2>/dev/null
sleep 1
systemctl enable --now stun-max

sleep 2
systemctl is-active --quiet stun-max && ok "Signal server running" || error "Server failed — run: journalctl -u stun-max -n 20"
systemctl is-active --quiet stun-max-stun && ok "STUN server running" || warn "STUN server not started"

# ─── Firewall ─────────────────────────────────────────────────

if command -v ufw &>/dev/null; then
    ufw allow ${PORT}/tcp comment "STUN Max" 2>/dev/null
    ufw allow ${STUN_PORT}/udp comment "STUN Max STUN" 2>/dev/null
elif command -v firewall-cmd &>/dev/null; then
    firewall-cmd --permanent --add-port=${PORT}/tcp --add-port=${STUN_PORT}/udp 2>/dev/null
    firewall-cmd --reload 2>/dev/null
fi

# ─── Detect IP ────────────────────────────────────────────────

SERVER_IP=$(curl -4 -fsSL ifconfig.me 2>/dev/null || curl -4 -fsSL icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')

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
echo -e "  ${CYAN}./stun_max-cli --server ws://${SERVER_IP}:${PORT}/ws --room myroom --password pass --name mypc${NC}"
echo ""
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
