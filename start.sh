#!/usr/bin/env bash
# =============================================================
# ISHA-X EDR — start.sh
# Starts the full EDR stack: Wazuh → Ingestor → Backend
#
# Usage:
#   bash start.sh
#
# Logs:
#   logs/wazuh.log        Wazuh container startup
#   logs/ingestor.log     Ingestor pipeline (live events)
#   logs/backend.log      FastAPI backend
#   logs/start.log        This script's own output
# =============================================================

# --- Colour helpers ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; echo "[INFO]  $*" >> "$LOG"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; echo "[ OK ]  $*" >> "$LOG"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; echo "[WARN]  $*" >> "$LOG"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; echo "[FAIL]  $*" >> "$LOG"; }
step()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}"; echo "" >> "$LOG"; echo "--- $* ---" >> "$LOG"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$ROOT/logs/start.log"
mkdir -p "$ROOT/logs"

echo "========================================" | tee -a "$LOG"
echo " ISHA-X start.sh — $(date)" | tee -a "$LOG"
echo "========================================" | tee -a "$LOG"

# =============================================================
# Load .env
# =============================================================
ENV_FILE="$ROOT/server/backend/.env"
if [ ! -f "$ENV_FILE" ]; then
  fail ".env not found at $ENV_FILE"
  fail "Run: bash setup.sh first"
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a
ok "Loaded .env"

# =============================================================
# STEP 1: Kill orphaned processes
# =============================================================
step "1/5 Stopping any running ISHA-X processes"

pkill -f "uvicorn main:app" 2>/dev/null && info "Killed old uvicorn" || true
pkill -f "python3 ingestor.py" 2>/dev/null && info "Killed old ingestor" || true
sleep 1
ok "Old processes cleared"

# =============================================================
# STEP 2: Auto-detect & update Tailscale IP
# =============================================================
step "2/5 Tailscale IP detection"

# Start tailscaled if not running
if ! pgrep -x tailscaled &>/dev/null; then
  warn "tailscaled not running — attempting to start..."
  sudo tailscaled --state=/var/lib/tailscale/tailscaled.state \
    --socket=/run/tailscale/tailscaled.sock >/dev/null 2>&1 &
  sleep 2
fi

TS_IP=$(tailscale ip -4 2>/dev/null || echo "")
if [ -n "$TS_IP" ]; then
  ok "Tailscale IP: $TS_IP"
  # Auto-update SERVER_HOST in .env if it changed
  CURRENT_HOST=$(grep '^SERVER_HOST=' "$ENV_FILE" 2>/dev/null | cut -d= -f2- || echo "")
  if [ "$CURRENT_HOST" != "$TS_IP" ]; then
    sed -i "s|^SERVER_HOST=.*|SERVER_HOST=$TS_IP|" "$ENV_FILE"
    warn "SERVER_HOST updated: $CURRENT_HOST → $TS_IP"
    warn "⚠️  Download a fresh agent from Dashboard after this change!"
  else
    ok "SERVER_HOST unchanged: $TS_IP"
  fi
  export SERVER_HOST="$TS_IP"
else
  warn "Tailscale not connected! Agent connections will fail."
  warn "In a new terminal, run: sudo tailscale up"
  warn "Then re-run: bash start.sh"
  # Don't exit — backend can still run for testing
fi

# =============================================================
# STEP 3: Start Wazuh Manager (Docker)
# =============================================================
step "3/5 Starting Wazuh Manager"

WAZUH_DIR="$ROOT/server/wazuh"
mkdir -p /tmp/wazuh_logs/archives /tmp/wazuh_logs/alerts /tmp/wazuh_logs/api /tmp/wazuh_logs/ossec
chmod -R 777 /tmp/wazuh_logs

if ! command -v docker &>/dev/null; then
  warn "Docker not found — Wazuh will not start. Agent events will not be collected."
else
  # Check if Wazuh container is already running
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "wazuh"; then
    ok "Wazuh container already running"
  else
    info "Starting Wazuh Manager container..."
    cd "$WAZUH_DIR"
    docker compose up -d >> "$ROOT/logs/wazuh.log" 2>&1 \
      && ok "Wazuh container started" \
      || { warn "docker compose failed — check logs/wazuh.log"; }
    cd "$ROOT"

    # Wait for Wazuh API to become ready (max 90s)
    info "Waiting for Wazuh API to be ready (max 90s)..."
    WAZUH_READY=0
    for i in $(seq 1 18); do
      sleep 5
      HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        -u "${WAZUH_API_USER:-wazuh-wui}:${WAZUH_API_PASS:-MyS3cr37P450r.*-}" \
        "https://localhost:55000/security/user/authenticate" 2>/dev/null || echo "000")
      if [ "$HTTP_CODE" = "200" ]; then
        WAZUH_READY=1
        ok "Wazuh API ready (took $((i*5))s)"
        break
      fi
      info "  ... still starting ($((i*5))s, HTTP=$HTTP_CODE)"
    done
    if [ "$WAZUH_READY" = "0" ]; then
      warn "Wazuh API not ready after 90s — continuing anyway"
      warn "Check: docker logs \$(docker ps -q --filter name=wazuh)"
    fi
  fi

  # =============================================================
  # Auto-sync: Register any unregistered Wazuh agents into master.db
  # This fixes the "DROPPED: agent_id not registered" problem
  # =============================================================
  info "Syncing Wazuh agents → master.db..."
  python3 "$ROOT/server/pipeline/sync_agents.py" 2>>"$LOG" \
    && ok "Agent sync complete" \
    || warn "Agent sync failed — check logs/start.log"
fi

# =============================================================
# STEP 4: Start Ingestor Pipeline
# =============================================================
step "4/5 Starting Ingestor Pipeline"

PIPELINE_DIR="$ROOT/server/pipeline"
INGESTOR_LOG="$ROOT/logs/ingestor.log"

cd "$PIPELINE_DIR"

# Build the environment for the ingestor
MULTI_TENANT=1 \
ARCHIVES_JSON=/tmp/wazuh_logs/archives/archives.json \
POLL_INTERVAL=0.5 \
  nohup python3 ingestor.py > "$INGESTOR_LOG" 2>&1 &

INGESTOR_PID=$!
sleep 1

if kill -0 "$INGESTOR_PID" 2>/dev/null; then
  ok "Ingestor started (PID=$INGESTOR_PID)"
  ok "Log: logs/ingestor.log"
  echo "$INGESTOR_PID" > "$ROOT/logs/ingestor.pid"
else
  fail "Ingestor failed to start!"
  fail "Check: tail -50 logs/ingestor.log"
fi

cd "$ROOT"

# =============================================================
# STEP 5: Start FastAPI Backend
# =============================================================
step "5/5 Starting FastAPI Backend"

BACKEND_DIR="$ROOT/server/backend"
BACKEND_LOG="$ROOT/logs/backend.log"

cd "$BACKEND_DIR"

nohup python3 -m uvicorn main:app \
  --host 0.0.0.0 \
  --port 8000 \
  > "$BACKEND_LOG" 2>&1 &

BACKEND_PID=$!
sleep 2

# Verify it's running
if kill -0 "$BACKEND_PID" 2>/dev/null; then
  ok "Backend started (PID=$BACKEND_PID)"
  ok "Log: logs/backend.log"
  echo "$BACKEND_PID" > "$ROOT/logs/backend.pid"
else
  fail "Backend failed to start!"
  fail "Check: tail -50 logs/backend.log"
fi

cd "$ROOT"

# =============================================================
# Health check
# =============================================================
sleep 2
HTTP=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000/health 2>/dev/null || echo "000")
if [ "$HTTP" = "200" ]; then
  ok "Health check passed (HTTP 200)"
else
  warn "Health check returned HTTP $HTTP — may still be starting"
fi

# =============================================================
# Summary
# =============================================================
echo ""
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}${BOLD}  ✅  ISHA-X EDR Stack is Running!${NC}"
echo -e "${GREEN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Dashboard  : (check Ports tab → port 8000)"
echo "  Tailscale  : ${TS_IP:-not connected}"
echo ""
echo "  Logs (tail -f to follow):"
echo "    logs/ingestor.log   ← live event pipeline"
echo "    logs/backend.log    ← API requests & errors"
echo "    logs/wazuh.log      ← Wazuh container startup"
echo ""
echo "  Quick checks:"
echo "    cat logs/ingestor.log | tail -20   # see recent events"
echo "    cat logs/backend.log  | tail -20   # see backend status"
echo ""
echo "[start.sh] Completed at $(date)" >> "$LOG"
