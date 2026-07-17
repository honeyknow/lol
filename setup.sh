#!/usr/bin/env bash
# =============================================================
# ISHA-X EDR — setup.sh
# Run ONCE after a fresh Codespace is created.
# This installs ALL prerequisites and configures the environment.
#
# Usage:
#   bash setup.sh
#
# Logs: ./logs/setup.log (errors also printed to terminal)
# =============================================================

set -euo pipefail

# --- Colour helpers ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; echo "[INFO]  $*" >> "$LOG"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; echo "[OK]    $*" >> "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; echo "[WARN]  $*" >> "$LOG"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; echo "[FAIL]  $*" >> "$LOG"; exit 1; }
step()  { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; echo "--- $* ---" >> "$LOG"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$ROOT/logs/setup.log"
mkdir -p "$ROOT/logs"
echo "========================================" >> "$LOG"
echo " ISHA-X setup.sh started at $(date)" >> "$LOG"
echo "========================================" >> "$LOG"

echo -e "${CYAN}"
echo "  ██╗███████╗██╗  ██╗ █████╗       ██╗  ██╗"
echo "  ██║██╔════╝██║  ██║██╔══██╗      ╚██╗██╔╝"
echo "  ██║███████╗███████║███████║ █████╗ ╚███╔╝ "
echo "  ██║╚════██║██╔══██║██╔══██║ ╚════╝ ██╔██╗ "
echo "  ██║███████║██║  ██║██║  ██║       ██╔╝ ██╗"
echo "  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝       ╚═╝  ╚═╝"
echo "  EDR — Setup Script"
echo -e "${NC}"

# =============================================================
# STEP 1: System Packages
# =============================================================
step "1/6 Installing system packages"

export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -qq 2>>"$LOG" || fail "apt-get update failed — check logs/setup.log"

PKGS=(
  curl wget git sqlite3 unzip
  nsis                              # NSIS compiler — builds Windows .exe agent installers
  jq                                # JSON parsing in bash
)

for pkg in "${PKGS[@]}"; do
  if dpkg -s "$pkg" &>/dev/null; then
    ok "$pkg already installed"
  else
    info "Installing $pkg..."
    sudo apt-get install -y "$pkg" 2>>"$LOG" \
      && ok "$pkg installed" \
      || warn "$pkg install failed (non-critical) — see logs/setup.log"
  fi
done

# =============================================================
# STEP 2: Tailscale
# =============================================================
step "2/6 Installing Tailscale VPN"

if command -v tailscale &>/dev/null; then
  ok "Tailscale already installed ($(tailscale version 2>/dev/null | head -1))"
else
  info "Downloading and installing Tailscale..."
  curl -fsSL https://tailscale.com/install.sh 2>>"$LOG" | sh >>"$LOG" 2>&1 \
    && ok "Tailscale installed" \
    || fail "Tailscale install failed — check logs/setup.log"
fi

# Start tailscaled daemon
if ! pgrep -x tailscaled &>/dev/null; then
  info "Starting tailscaled daemon..."
  sudo tailscaled --state=/var/lib/tailscale/tailscaled.state \
    --socket=/run/tailscale/tailscaled.sock \
    >/dev/null 2>&1 &
  sleep 2
  ok "tailscaled started (PID=$!)"
else
  ok "tailscaled already running"
fi

# Tailscale authentication
ENV_FILE="$ROOT/server/backend/.env"
TAILSCALE_AUTH_KEY=""
if [ -f "$ENV_FILE" ]; then
  TAILSCALE_AUTH_KEY=$(grep -E '^TAILSCALE_AUTH_KEY=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || true)
fi

if [ -n "$TAILSCALE_AUTH_KEY" ]; then
  info "Connecting Tailscale with auth key from .env..."
  sudo tailscale up --authkey="$TAILSCALE_AUTH_KEY" --accept-routes 2>>"$LOG" \
    && ok "Tailscale connected via auth key" \
    || warn "Tailscale auth key connect failed. Run: sudo tailscale up"
else
  warn "No TAILSCALE_AUTH_KEY in .env — opening browser for manual auth..."
  warn "Run in a new terminal: sudo tailscale up"
  warn "Then paste the URL in your browser and authenticate."
  # Non-blocking — user handles manually
  sudo tailscale up 2>>"$LOG" &
  sleep 3
fi

TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -n "$TS_IP" ]; then
  ok "Tailscale IP: $TS_IP"
  # Auto-update SERVER_HOST in .env
  if [ -f "$ENV_FILE" ]; then
    if grep -q '^SERVER_HOST=' "$ENV_FILE"; then
      sed -i "s|^SERVER_HOST=.*|SERVER_HOST=$TS_IP|" "$ENV_FILE"
      ok "Updated SERVER_HOST=$TS_IP in .env"
    fi
  fi
else
  warn "Tailscale not yet connected — manually run: sudo tailscale up"
  warn "Then update SERVER_HOST in server/backend/.env"
fi

# =============================================================
# STEP 3: Python Dependencies
# =============================================================
step "3/6 Installing Python dependencies"

info "Installing backend dependencies..."
pip install --quiet -r "$ROOT/server/backend/requirements.txt" >>"$LOG" 2>&1 \
  && ok "Backend deps installed" \
  || fail "Backend pip install failed — check logs/setup.log"

info "Installing pipeline dependencies..."
pip install --quiet -r "$ROOT/server/pipeline/requirements.txt" >>"$LOG" 2>&1 \
  && ok "Pipeline deps installed" \
  || fail "Pipeline pip install failed — check logs/setup.log"

# =============================================================
# STEP 4: .env file check
# =============================================================
step "4/6 Checking .env configuration"

EXAMPLE_ENV="$ROOT/server/backend/.env.example"
if [ ! -f "$ENV_FILE" ]; then
  if [ -f "$EXAMPLE_ENV" ]; then
    cp "$EXAMPLE_ENV" "$ENV_FILE"
    warn ".env not found — copied from .env.example"
    warn "⚠️  IMPORTANT: Edit server/backend/.env and fill in your values!"
  else
    fail ".env and .env.example both missing! Cannot continue."
  fi
else
  ok ".env file exists"
fi

# Verify critical keys exist
for KEY in GROQ_API_KEY ADMIN_EMAILS SESSION_SECRET WAZUH_API_USER WAZUH_API_PASS; do
  if grep -q "^${KEY}=" "$ENV_FILE" 2>/dev/null; then
    ok "$KEY is set"
  else
    warn "$KEY is missing from .env — some features may not work"
  fi
done

# =============================================================
# STEP 5: Database setup
# =============================================================
step "5/6 Initialising databases"

PIPELINE_DIR="$ROOT/server/pipeline"
mkdir -p "$PIPELINE_DIR/tenants"

# Initialize master.db if it's empty/missing
if [ ! -s "$PIPELINE_DIR/master.db" ]; then
  info "Initialising master.db from schema..."
  python3 - <<'PYEOF' >> "$LOG" 2>&1
import sqlite3, os, sys
from pathlib import Path
pipeline = Path(os.environ.get("PIPELINE_DIR", "/workspaces/ishax/server/pipeline"))
schema_file = pipeline / "master_schema.sql"
db_file = pipeline / "master.db"
if schema_file.exists():
    con = sqlite3.connect(str(db_file))
    con.executescript(schema_file.read_text())
    con.commit()
    con.close()
    print(f"master.db initialised from {schema_file}")
else:
    print("master_schema.sql not found — master.db will be auto-created by app")
PYEOF
  ok "master.db ready"
else
  ok "master.db already exists ($(du -sh "$PIPELINE_DIR/master.db" | cut -f1))"
fi

# =============================================================
# STEP 6: Docker / Wazuh Check
# =============================================================
step "6/6 Verifying Docker"

if command -v docker &>/dev/null; then
  DOCKER_VER=$(docker --version 2>/dev/null)
  ok "Docker available: $DOCKER_VER"
  # Test docker daemon is running
  if docker info &>/dev/null 2>&1; then
    ok "Docker daemon is running"
  else
    warn "Docker daemon not running — start.sh will try to start it"
  fi
else
  warn "Docker not found — Wazuh Manager won't start"
  warn "Rebuild the Codespace if Docker is missing"
fi

# Make start.sh executable
chmod +x "$ROOT/start.sh" 2>/dev/null || true

# =============================================================
# Summary
# =============================================================
echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅  ISHA-X Setup Complete!${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Next steps:"
if [ -z "$TS_IP" ]; then
  echo -e "  ${YELLOW}1. Run: sudo tailscale up  (authenticate Tailscale)${NC}"
  echo    "  2. Update SERVER_HOST in server/backend/.env with your Tailscale IP"
  echo    "  3. Run: bash start.sh"
else
  echo    "  1. Run: bash start.sh"
fi
echo ""
echo "  Setup log: logs/setup.log"
echo ""
echo "[setup.sh] Completed at $(date)" >> "$LOG"
