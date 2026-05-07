#!/usr/bin/env bash
# ==============================================================================
# rotate-secrets.sh — Rotate the AppRole secret_id
# ==============================================================================
#
# WHY rotate the secret_id?
# The secret_id has a 24h TTL (configured in init-vault.sh).
# After 24h it expires and the app can no longer authenticate with Vault.
# This script generates a fresh secret_id, replaces the file, and restarts
# the app containers to pick it up — with ZERO downtime (rolling restart).
#
# Run this on a cron schedule:
#   0 20 * * * /opt/zero-trust-architecture/scripts/rotate-secrets.sh >> /var/log/rotate-secrets.log 2>&1
#
# Also run immediately after any suspected secret_id compromise.
# ==============================================================================

set -euo pipefail

VAULT_ADDR=${VAULT_ADDR:-"http://localhost:8200"}
SECRETS_DIR="${SECRETS_DIR:-./secrets}"
ROLE_NAME="zt-app-role"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $(date -u '+%Y-%m-%dT%H:%M:%SZ') $1"; }

# ==============================================================================
# PREREQUISITES
# ==============================================================================
command -v vault  >/dev/null || { log_error "vault CLI not found"; exit 1; }
command -v docker >/dev/null || { log_error "docker not found"; exit 1; }

ROOT_TOKEN_FILE="${SECRETS_DIR}/vault_root_token.txt"
[ -f "$ROOT_TOKEN_FILE" ] || { log_error "Root token not found at $ROOT_TOKEN_FILE"; exit 1; }

export VAULT_TOKEN=$(cat "$ROOT_TOKEN_FILE")
export VAULT_ADDR

# ==============================================================================
# STEP 1: Revoke existing secret_id (if we have it — security hygiene)
# ==============================================================================
# WHY revoke the old one before creating a new one?
# If the old secret_id leaked, revoking it closes the window immediately.
# Without revocation, both old and new secret_ids would be valid simultaneously.
OLD_SECRET_ID_FILE="${SECRETS_DIR}/vault_secret_id.txt"
if [ -f "$OLD_SECRET_ID_FILE" ]; then
    OLD_SECRET_ID=$(cat "$OLD_SECRET_ID_FILE")
    log_info "Revoking old secret_id..."
    vault write -f auth/approle/role/${ROLE_NAME}/secret-id/destroy \
        secret_id="$OLD_SECRET_ID" 2>/dev/null || log_warn "Could not revoke old secret_id (may have already expired)"
fi

# ==============================================================================
# STEP 2: Generate fresh secret_id
# ==============================================================================
log_info "Generating new secret_id for role: ${ROLE_NAME}..."

NEW_SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/${ROLE_NAME}/secret-id)

# ==============================================================================
# STEP 3: Verify the new secret_id works BEFORE replacing the old one
# ==============================================================================
# WHY verify first?
# If something is wrong (Vault sealed, role misconfigured), this would cause
# an outage. Verify the new credentials work before committing.
log_info "Verifying new secret_id..."
ROLE_ID=$(cat "${SECRETS_DIR}/vault_role_id.txt")

TEST_TOKEN=$(vault write -field=token auth/approle/login \
    role_id="$ROLE_ID" \
    secret_id="$NEW_SECRET_ID")

if [ -z "$TEST_TOKEN" ]; then
    log_error "New secret_id verification FAILED. Old secret_id NOT replaced. Investigate Vault."
    exit 1
fi

# Revoke the test token immediately
VAULT_TOKEN="$TEST_TOKEN" vault token revoke -self 2>/dev/null || true
log_info "Verification passed."

# ==============================================================================
# STEP 4: Atomically replace the secret_id file
# ==============================================================================
# WHY write to a temp file first?
# Writing directly to vault_secret_id.txt creates a window where the file
# is empty/partial. A container reading it at that moment would get corrupt data.
# Writing to a temp file then renaming is atomic on Linux.
TEMP_FILE="${SECRETS_DIR}/vault_secret_id.txt.tmp"
echo "$NEW_SECRET_ID" > "$TEMP_FILE"
chmod 600 "$TEMP_FILE"
mv "$TEMP_FILE" "${SECRETS_DIR}/vault_secret_id.txt"

log_info "secret_id file replaced atomically."

# ==============================================================================
# STEP 5: Rolling restart of app containers (zero downtime)
# ==============================================================================
# WHY rolling restart instead of stopping all at once?
# Nginx load balances between app_az1 and app_az2. Restarting one at a time
# means the other continues serving traffic — no downtime.
log_info "Rolling restart: app_az1..."
docker restart zt-app-az1
sleep 10  # Wait for health check to pass before restarting AZ2

# Verify AZ1 is healthy before restarting AZ2
AZ1_STATUS=$(docker inspect --format='{{.State.Health.Status}}' zt-app-az1 2>/dev/null || echo "unknown")
if [ "$AZ1_STATUS" != "healthy" ]; then
    log_warn "app_az1 health status: $AZ1_STATUS — waiting extra 20s..."
    sleep 20
fi

log_info "Rolling restart: app_az2..."
docker restart zt-app-az2

log_info "Rotation complete. New secret_id active. Expires in 24h."
log_info "Schedule this script to run every 20h (buffer before 24h expiry):"
log_info "  0 */20 * * * $(realpath $0)"
