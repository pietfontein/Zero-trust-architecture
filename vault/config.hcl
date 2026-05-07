# ==============================================================================
# HashiCorp Vault Configuration
# ==============================================================================
#
# WHY HASHICORP VAULT?
#   Most applications handle secrets poorly:
#     ❌ Hardcoded in source code (committed to git forever)
#     ❌ Environment variables (visible in `docker inspect`, ps aux)
#     ❌ .env files (often committed accidentally)
#     ❌ Config files (rotation requires redeploy)
#
#   Vault solves all of these:
#     ✅ Secrets encrypted at rest (AES-256-GCM)
#     ✅ Secrets encrypted in transit (TLS)
#     ✅ Full audit log: every secret read is logged with timestamp + identity
#     ✅ Dynamic secrets: unique credentials per service, auto-rotated
#     ✅ Lease system: secrets expire automatically
#     ✅ Break-glass: revoke all credentials instantly in an incident
#
# VAULT ARCHITECTURE:
#   Vault stores secrets in a "backend" (we use the filesystem for local dev,
#   use Consul or cloud KMS for production).
#   Vault is SEALED at startup — unseal keys required to decrypt storage.
#   This means even with physical disk access, secrets are unreadable.
#
# ==============================================================================

# Storage backend
# WHY "file" for local dev?
# File backend is simple and works with a single Vault instance.
# For production: use "raft" (built-in clustering) or "consul" (external cluster)
storage "file" {
  path = "/vault/data"
}

# Listener: how Vault accepts connections
listener "tcp" {
  address = "0.0.0.0:8200"
  
  # WHY tls_disable in dev?
  # TLS requires certificates. For local dev, we skip it.
  # In production: ALWAYS enable TLS.
  # tls_disable = "false"
  # tls_cert_file = "/vault/tls/vault.crt"
  # tls_key_file  = "/vault/tls/vault.key"
  tls_disable = "true"  # ← Change to false in production
}

# Disable mlock requirement for dev (non-root containers can't mlock)
# In production: set up system limits or use the IPC_LOCK capability (already in docker-compose.yml)
disable_mlock = true

# API address for cluster coordination
api_addr = "http://vault:8200"

# UI: enable the web dashboard (disable in production if not needed)
ui = true
