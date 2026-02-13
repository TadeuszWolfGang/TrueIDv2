#!/usr/bin/env bash
set -euo pipefail

# TrueID Installation Script (bare metal / VM)
# Run as root or with sudo

INSTALL_DIR="/opt/trueid"
TRUEID_USER="trueid"

echo "=== TrueID Installation ==="

# Create user
if ! id "$TRUEID_USER" &>/dev/null; then
    useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$TRUEID_USER"
    echo "Created user: $TRUEID_USER"
fi

# Create directories
mkdir -p "$INSTALL_DIR"/{bin,data,backups,tls,scripts}

# Copy binaries (assumes they're built already)
if [ -f target/release/trueid-engine ]; then
    cp target/release/trueid-engine "$INSTALL_DIR/bin/"
    cp target/release/trueid-web "$INSTALL_DIR/bin/"
    echo "Binaries installed."
else
    echo "ERROR: Build first with: cargo build --release"
    exit 1
fi

# Copy assets
cp -r apps/web/assets "$INSTALL_DIR/"

# Copy scripts
cp scripts/backup.sh scripts/restore.sh "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts/"*.sh

# Copy .env template
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp .env.example "$INSTALL_DIR/.env"
    echo "Created .env — edit with production values!"
fi

# Fix permissions
chown -R "$TRUEID_USER:$TRUEID_USER" "$INSTALL_DIR"

# Install systemd units
cp deploy/systemd/trueid-engine.service /etc/systemd/system/
cp deploy/systemd/trueid-web.service /etc/systemd/system/
cp deploy/systemd/trueid-backup.service /etc/systemd/system/
cp deploy/systemd/trueid-backup.timer /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit /opt/trueid/.env with production secrets"
echo "     (generate with: make secrets)"
echo "  2. Start services:"
echo "     systemctl enable --now trueid-engine"
echo "     systemctl enable --now trueid-web"
echo "     systemctl enable --now trueid-backup.timer"
echo "  3. Configure firewall rules for UDP ports 1813, 5514, 5516, 5518"
echo "  4. Set up reverse proxy (see deploy/nginx/ or deploy/caddy/)"
echo "  5. Open https://trueid.example.com and login"
