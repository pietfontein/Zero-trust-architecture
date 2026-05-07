# ==============================================================================
# Vault Policy: app-policy
# ==============================================================================
#
# PRINCIPLE OF LEAST PRIVILEGE:
#   The app server can only access secrets it actually needs.
#   It CANNOT:
#     - Read Vault configuration
#     - Access other services' secrets
#     - Create/delete secrets
#     - Revoke tokens
#     - Access root paths
#
#   WHY does this matter?
#   If the app server is compromised, the attacker gets the app's Vault token.
#   With this policy, they can only read what the app can read.
#   They cannot escalate to read database admin passwords or other services.
#
# ==============================================================================

# Allow reading database credentials (dynamic secrets — auto-rotated)
path "database/creds/app-role" {
  capabilities = ["read"]
  # read = get a new set of temporary DB credentials
  # That's ALL. Cannot list other roles, cannot configure the DB engine.
}

# Allow reading Redis password
path "secret/data/redis/password" {
  capabilities = ["read"]
}

# Allow reading app-specific secrets (session key, API keys, etc.)
path "secret/data/app/*" {
  capabilities = ["read"]
}

# Allow the app to renew its own token (so it doesn't expire mid-operation)
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow the app to look up its own token info (for debugging)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# EXPLICITLY DENY sensitive paths (belt and suspenders)
path "sys/*" {
  capabilities = ["deny"]
}

path "auth/token/create*" {
  capabilities = ["deny"]
}

path "secret/data/database/admin*" {
  capabilities = ["deny"]
}
