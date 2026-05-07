#!/usr/bin/env bash
# ==============================================================================
# init-vault.sh — Initialize Vault and bootstrap all secrets
# ==============================================================================
#
# Run this ONCE after first deployment.
# It will:
#   1. Initialize Vault (creates unseal keys and root token)
#   2. Unseal Vault (makes secrets accessible)
#   3. Configure the database secrets engine (dynamic credentials)
#   4. Configure the KV secrets engine (static secrets)
#   5. Create the app policy (least privilege)
#   6. Create the app token (what the app uses to authenticate)
#   7. Generate initial secrets and write to ./secrets/ directory
#
# IMPORTANT: The unseal keys and root token are HIGHLY SENSITIVE.
# In production: store unseal keys in separate secure locations (AWS KMS,
# HSM, etc.) — never in one place, never on the same host as Vault.
# ==============================================================================

set -euo pipefail  # Exit on any error, undefined variable, or pipe failure

VAULT_ADDR=${VAULT_ADDR:-"http://localhost:8200"}
SECRETS_DIR="./secrets"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# ==============================================================================
# STEP 0: Prerequisites check
# ==============================================================================
log_info "Checking prerequisites..."

command -v vault  >/dev/null || { log_error "vault CLI not found. Install HashiCorp Vault."; exit 1; }
command -v docker >/dev/null || { log_error "docker not found."; exit 1; }
command -v openssl >/dev/null || { log_error "openssl not found."; exit 1; }

# Create secrets directory with restrictive permissions
# WHY 700? Only the current user can read/write/execute the directory.
# Group and others have NO access.
mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

# ==============================================================================
# STEP 1: Wait for Vault to be ready
# ==============================================================================
log_info "Waiting for Vault to start..."
for i in {1..30}; do
    if curl -sf "${VAULT_ADDR}/v1/sys/health" >/dev/null 2>&1; then
        log_info "Vault is ready."
        break
    fi
    echo -n "."
    sleep 2
done

# ==============================================================================
# STEP 2: Initialize Vault (only if not already initialized)
# ==============================================================================
VAULT_STATUS=$(vault status -format=json 2>/dev/null || echo '{"initialized":false}')
INITIALIZED=$(echo "$VAULT_STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('initialized', False))")

if [ "$INITIALIZED" = "False" ]; then
    log_info "Initializing Vault..."
    
    # -key-shares=5: Create 5 unseal key shards
    # -key-threshold=3: Need 3 of 5 shards to unseal (Shamir's Secret Sharing)
    # WHY Shamir's Secret Sharing?
    # If one key holder goes rogue or is compromised, they can't unseal alone.
    # Any 3 of 5 key holders must cooperate. This prevents single-person control.
    # For local dev, we use 1 key for simplicity.
    INIT_OUTPUT=$(vault operator init \
        -key-shares=1 \
        -key-threshold=1 \
        -format=json)
    
    UNSEAL_KEY=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['unseal_keys_b64'][0])")
    ROOT_TOKEN=$(echo "$INIT_OUTPUT" | python3 -c "import sys,json; print(json.load(sys.stdin)['root_token'])")
    
    # Save keys with restrictive permissions
    echo "$UNSEAL_KEY" > "${SECRETS_DIR}/vault_unseal_key.txt"
    echo "$ROOT_TOKEN" > "${SECRETS_DIR}/vault_root_token.txt"
    chmod 600 "${SECRETS_DIR}/vault_unseal_key.txt"
    chmod 600 "${SECRETS_DIR}/vault_root_token.txt"
    
    log_warn "CRITICAL: Unseal key saved to ${SECRETS_DIR}/vault_unseal_key.txt"
    log_warn "CRITICAL: Root token saved to ${SECRETS_DIR}/vault_root_token.txt"
    log_warn "In production: distribute unseal keys to separate secure locations."
else
    log_info "Vault already initialized."
    ROOT_TOKEN=$(cat "${SECRETS_DIR}/vault_root_token.txt")
    UNSEAL_KEY=$(cat "${SECRETS_DIR}/vault_unseal_key.txt")
fi

# ==============================================================================
# STEP 3: Unseal Vault
# ==============================================================================
SEALED=$(vault status -format=json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('sealed', True))")

if [ "$SEALED" = "True" ]; then
    log_info "Unsealing Vault..."
    vault operator unseal "$UNSEAL_KEY"
    log_info "Vault unsealed."
else
    log_info "Vault already unsealed."
fi

export VAULT_TOKEN="$ROOT_TOKEN"

# ==============================================================================
# STEP 4: Enable secrets engines
# ==============================================================================
log_info "Configuring secrets engines..."

# KV v2: key-value store for static secrets (API keys, config values)
# WHY v2 over v1?
# KV v2 supports versioning — you can roll back to a previous secret value.
# If a rotation goes wrong, `vault kv rollback` restores the previous version.
vault secrets enable -path=secret kv-v2 2>/dev/null || log_info "KV already enabled"

# Database secrets engine: dynamic credentials for PostgreSQL
# WHY dynamic secrets?
# Each request creates a UNIQUE, TEMPORARY PostgreSQL user.
# The user expires after 24 hours (configurable).
# Audit logs show WHICH app instance connected and WHEN.
# Rotation is automatic — no manual password rotation needed.
vault secrets enable database 2>/dev/null || log_info "Database engine already enabled"

# ==============================================================================
# STEP 5: Generate secrets and write to files
# ==============================================================================
log_info "Generating secrets..."

# Generate a cryptographically random PostgreSQL password
# WHY 32 bytes (256 bits)?
# More than enough entropy. Password crackers can't brute-force 256-bit randoms.
POSTGRES_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
MINIO_USER="minio-admin"
MINIO_PASSWORD=$(openssl rand -base64 32)
SESSION_KEY=$(openssl rand -base64 64)

# Write to secrets files (Docker reads these as Docker Secrets)
echo "$POSTGRES_PASSWORD" > "${SECRETS_DIR}/postgres_password.txt"
echo "$REDIS_PASSWORD" > "${SECRETS_DIR}/redis_password.txt"
echo "$MINIO_USER" > "${SECRETS_DIR}/minio_user.txt"
echo "$MINIO_PASSWORD" > "${SECRETS_DIR}/minio_password.txt"
chmod 600 "${SECRETS_DIR}"/*.txt

# Store in Vault KV
vault kv put secret/redis/password value="$REDIS_PASSWORD"
vault kv put secret/minio/credentials user="$MINIO_USER" password="$MINIO_PASSWORD"
vault kv put secret/app/session_key value="$SESSION_KEY"

# ==============================================================================
# STEP 6: Configure database secrets engine
# ==============================================================================
log_info "Configuring PostgreSQL dynamic secrets..."

# Tell Vault how to connect to PostgreSQL as admin (to create/revoke users)
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    allowed_roles="app-role" \
    connection_url="postgresql://{{username}}:{{password}}@postgres_primary:5432/appdb?sslmode=require" \
    username="postgres" \
    password="$POSTGRES_PASSWORD"

# Define the "app-role": what kind of user Vault creates for the app
# WHY GRANT SELECT, INSERT, UPDATE only?
# The app role cannot DROP TABLE, TRUNCATE, or ALTER — limits breach damage.
# Even if the app is compromised, the attacker can't destroy the database schema.
vault write database/roles/app-role \
    db_name=postgresql \
    creation_statements="
        CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
        GRANT CONNECT ON DATABASE appdb TO \"{{name}}\";
        GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";
        GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO \"{{name}}\";
    " \
    revocation_statements="DROP ROLE IF EXISTS \"{{name}}\";" \
    default_ttl="24h" \
    max_ttl="48h"

# ==============================================================================
# STEP 7: Write app-policy (least privilege)
# ==============================================================================
log_info "Writing app-policy..."

vault policy write app-policy ./vault/policies/app-policy.hcl

# ==============================================================================
# STEP 8: Enable and configure AppRole auth
# ==============================================================================
# WHY AppRole over a static token?
#
# Static token (old approach):
#   One secret file. Stolen once = permanent Vault access until manually revoked.
#   No expiry. No audit trail of which service used it.
#
# AppRole (two-factor for machines):
#   role_id   — not secret. Like a username. Can be baked into the image.
#   secret_id — secret. Like a password. Injected at runtime. Time-limited.
#   An attacker needs BOTH. Stealing one file is not enough.
#
# Additional AppRole security properties we configure:
#   token_ttl=1h         — tokens expire in 1h, limiting breach window
#   secret_id_ttl=24h    — secret_id rotates every 24h automatically
#   secret_id_num_uses=0 — unlimited uses within TTL (set to 1 for single-use in prod)
#   token_policies       — token inherits only app-policy (least privilege)

log_info "Configuring AppRole auth..."

vault auth enable approle 2>/dev/null || log_info "AppRole already enabled"

# Create the AppRole role bound to app-policy
vault write auth/approle/role/zt-app-role     token_policies="app-policy"     token_ttl=1h     token_max_ttl=4h     secret_id_ttl=24h     secret_id_num_uses=0

# Read the role_id (this is NOT secret — it identifies which role to use)
# WHY save role_id to a file?
# role_id is semi-public (like a username). It identifies the role but cannot
# authenticate alone. We store it as a Docker secret for convenience, not secrecy.
ROLE_ID=$(vault read -field=role_id auth/approle/role/zt-app-role/role-id)
echo "$ROLE_ID" > "${SECRETS_DIR}/vault_role_id.txt"
chmod 644 "${SECRETS_DIR}/vault_role_id.txt"  # role_id is not secret

# Generate a secret_id (THIS is the secret half — treat like a password)
# WHY -wrap-ttl=120s?
# The secret_id is returned wrapped in a response-wrapping token.
# Only the app that unwraps it within 120s gets the actual secret_id.
# Even if someone intercepts the wrapped token, it expires in 2 minutes.
# For local dev we skip wrapping (unwrap adds complexity); enable in production.
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/zt-app-role/secret-id)
echo "$SECRET_ID" > "${SECRETS_DIR}/vault_secret_id.txt"
chmod 600 "${SECRETS_DIR}/vault_secret_id.txt"  # secret_id IS secret

log_warn "AppRole credentials written:"
log_info "  📋 vault_role_id.txt   — semi-public, identifies the role"
log_warn "  🔑 vault_secret_id.txt — SECRET, rotates every 24h"

# ==============================================================================
# STEP 9: Verify AppRole login works before finishing
# ==============================================================================
log_info "Verifying AppRole login..."

TEST_TOKEN=$(vault write -field=token auth/approle/login     role_id="$ROLE_ID"     secret_id="$SECRET_ID")

if [ -n "$TEST_TOKEN" ]; then
    log_info "AppRole login successful — token obtained."
    # Revoke the test token immediately (we only needed to verify it works)
    VAULT_TOKEN="$TEST_TOKEN" vault token revoke -self 2>/dev/null || true
else
    log_error "AppRole login FAILED. Check role config and policy."
    exit 1
fi

# ==============================================================================
# COMPLETE
# ==============================================================================
log_info "==========================================="
log_info "Vault initialization complete!"
log_info "==========================================="
log_info ""
log_info "Secrets written to: ${SECRETS_DIR}/"
log_info "  ⚠️  vault_unseal_key.txt  — BACK UP SECURELY (offline)"
log_info "  ⚠️  vault_root_token.txt  — USE ONLY FOR ADMIN, REVOKE AFTER"
log_info "  📋  vault_role_id.txt     — semi-public, safe to share with app"
log_info "  🔑  vault_secret_id.txt   — SECRET — rotates every 24h"
log_info ""
log_info "Next: terraform init && terraform apply"
log_info "To rotate secret_id (run every 24h or on breach):"
log_info "  ./scripts/rotate-secrets.sh"
