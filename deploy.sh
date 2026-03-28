#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  OmniAudit — Fly.io deploy script
#  Usage:
#    First deploy:   ./fly-deploy.sh --init
#    Redeploy:       ./fly-deploy.sh
#
#  Prerequisites:
#    fly CLI installed and authenticated (`fly auth login`)
#    Docker running locally
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

APP="omniaudit"
REGION="lhr"           # change to your nearest region (sin, iad, syd, fra…)
POSTGRES_APP="${APP}-db"

# ── Colour helpers ─────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}>>>${NC} $*"; }
warn()    { echo -e "${YELLOW}!!! $*${NC}"; }
die()     { echo -e "${RED}ERR $*${NC}" >&2; exit 1; }

# ── Prereq check ──────────────────────────────────────────────────────────────
command -v fly   >/dev/null 2>&1 || die "fly CLI not found. Install: https://fly.io/docs/hands-on/install-flyctl/"
command -v docker>/dev/null 2>&1 || die "Docker not found."
fly auth whoami  >/dev/null 2>&1 || die "Not logged into Fly. Run: fly auth login"

INIT_MODE=false
[[ "${1:-}" == "--init" ]] && INIT_MODE=true

# ══════════════════════════════════════════════════════════════════════════════
#  FIRST-TIME INIT
# ══════════════════════════════════════════════════════════════════════════════
if $INIT_MODE; then
    info "=== FIRST-TIME INIT MODE ==="

    # 1. Create the Fly app
    info "Creating Fly app: ${APP}"
    fly apps create "${APP}" --region "${REGION}" || warn "App may already exist — continuing"

    # 2. Provision Fly Postgres (free tier: 256 MB, 1 CPU)
    info "Provisioning Fly Postgres cluster: ${POSTGRES_APP}"
    fly postgres create \
        --name "${POSTGRES_APP}" \
        --region "${REGION}" \
        --initial-cluster-size 1 \
        --vm-size shared-cpu-1x \
        --volume-size 1 \
        || warn "Postgres cluster may already exist — continuing"

    # 3. Attach Postgres — this sets DATABASE_URL secret automatically
    # IMPORTANT: Fly injects DATABASE_URL as postgres://... format.
    # asyncpg accepts postgres:// directly — do NOT add +asyncpg suffix.
    info "Attaching Postgres to app (sets DATABASE_URL secret automatically)"
    fly postgres attach "${POSTGRES_APP}" --app "${APP}" \
        || warn "Already attached — continuing"

    # 4. Create persistent volume for Moltbook credentials / patrol state
    info "Creating persistent volume: omniaudit_data (1 GB)"
    fly volumes create omniaudit_data \
        --app "${APP}" \
        --region "${REGION}" \
        --size 1 \
        || warn "Volume may already exist — continuing"

    # 5. Generate a sovereign Ed25519 key if the user doesn't have one
    echo ""
    warn "SOVEREIGN KEY SETUP"
    echo "  If you don't have a key yet, generate one:"
    echo "    python3 -c \""
    echo "    from cryptography.hazmat.primitives.asymmetric import ed25519"
    echo "    k = ed25519.Ed25519PrivateKey.generate()"
    echo "    print(k.private_bytes_raw().hex())\""
    echo ""
    echo "  Then set it as a secret (next step will prompt for all secrets)."
    echo ""

    # 6. Set secrets interactively
    info "Setting secrets — you will be prompted for each value"
    echo "  (Values are encrypted and never stored in fly.toml)"
    echo ""

    read -r -s -p "WALLET_ADDRESS (your USDC wallet on Base): "    WALLET_ADDRESS
    echo ""
    read -r -s -p "SOVEREIGN_KEY_HEX (64-char hex Ed25519 key): "  SOVEREIGN_KEY_HEX
    echo ""
    read -r -s -p "ADMIN_TOKEN (random secret, min 32 chars): "     ADMIN_TOKEN
    echo ""
    read -r -s -p "GEMINI_API_KEY (Google AI Studio key): "         GEMINI_API_KEY
    echo ""

    [[ ${#ADMIN_TOKEN} -lt 32 ]] && die "ADMIN_TOKEN must be at least 32 characters."
    [[ ${#SOVEREIGN_KEY_HEX} -ne 64 ]] && die "SOVEREIGN_KEY_HEX must be exactly 64 hex chars."

    fly secrets set \
        --app "${APP}" \
        "WALLET_ADDRESS=${WALLET_ADDRESS}" \
        "SOVEREIGN_KEY_HEX=${SOVEREIGN_KEY_HEX}" \
        "ADMIN_TOKEN=${ADMIN_TOKEN}" \
        "GEMINI_API_KEY=${GEMINI_API_KEY}"

    info "Secrets set successfully."
    echo ""
    info "=== Init complete. Running first deploy... ==="
    echo ""
fi

# ══════════════════════════════════════════════════════════════════════════════
#  DEPLOY (runs on both --init and subsequent deploys)
# ══════════════════════════════════════════════════════════════════════════════

info "Deploying ${APP} to Fly.io (region: ${REGION})"

# fly deploy builds and pushes the image, then does a rolling restart.
# --ha=false: we run a single machine; Fly HA would spin a second which
#             doubles cost and the pg advisory lock already handles safety.
fly deploy \
    --app "${APP}" \
    --config fly.toml \
    --ha=false \
    --strategy rolling

info "Deploy complete."
echo ""

# ── Post-deploy checks ─────────────────────────────────────────────────────────
info "Running post-deploy health check..."
sleep 5

HEALTH=$(curl -sf "https://${APP}.fly.dev/health" 2>/dev/null || echo "FAILED")
if echo "${HEALTH}" | grep -q '"status":"ok"'; then
    info "Health check passed: ${HEALTH}"
else
    warn "Health check response: ${HEALTH}"
    warn "Check logs: fly logs --app ${APP}"
fi

echo ""
info "Useful commands:"
echo "  fly logs --app ${APP}                 — tail live logs"
echo "  fly status --app ${APP}               — machine status"
echo "  fly ssh console --app ${APP}          — shell into container"
echo "  fly volumes list --app ${APP}         — check /app/data volume"
echo "  fly secrets list --app ${APP}         — list secret keys (not values)"
echo ""
echo "  # Trigger patrol manually:"
echo "  ADMIN=\$(fly secrets show --app ${APP} ADMIN_TOKEN --json | jq -r '.ADMIN_TOKEN')"
echo "  curl -s -X POST https://${APP}.fly.dev/patrol/trigger -H \"X-Admin-Token: \${ADMIN}\""
echo ""
echo "  # Update MOLTBOOK_API if Meta/MSL migrate the endpoint:"
echo "  fly secrets set MOLTBOOK_API=https://new-endpoint.example.com/api/v1 --app ${APP}"
echo "  # OR update fly.toml [env] and redeploy (it's non-secret)"
echo ""

info "Done."
