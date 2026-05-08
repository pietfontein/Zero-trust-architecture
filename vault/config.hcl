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


storage "file" {
  path = "/vault/data"
}


listener "tcp" {
  address = "0.0.0.0:8200"


  tls_disable = "true"  # ← Change to false in production
}


disable_mlock = true


api_addr = "http://vault:8200"


ui = true
