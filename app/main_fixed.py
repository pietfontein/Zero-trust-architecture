"""
==============================================================================
Zero-Trust Web Application — Flask + Gunicorn + AppRole Vault Auth
==============================================================================
"""

import os
import logging
import threading
import time
from urllib.parse import quote

import bcrypt
import hvac
import psycopg2
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from sanitize import InputSanitizer, SanitizationError

logging.basicConfig(
    format='{"time":"%(asctime)s","level":"%(levelname)s","module":"%(module)s","msg":"%(message)s"}',
    level=logging.INFO
)
logger = logging.getLogger(__name__)


# ==============================================================================
# APPROLE VAULT CLIENT
# ==============================================================================
# WHY AppRole over a static Vault token?
#
# Static token (old approach):
#   One secret file → stolen once = permanent access until manually revoked.
#   No expiry. If the file leaks, you don't know until damage is done.
#
# AppRole (two-factor auth for machines):
#   role_id   → semi-public. Identifies WHICH role. Like a username.
#               Safe to appear in logs, docker inspect, config files.
#   secret_id → secret. TIME-LIMITED (24h TTL). Like a password.
#               Must never appear in logs or env vars.
#   An attacker needs BOTH files simultaneously. Stealing one is not enough.
#
# Additional security properties:
#   token_ttl=1h     → even if a token leaks, it expires in 1 hour
#   secret_id_ttl=24h → rotate daily via rotate-secrets.sh
#   Each login call produces a NEW short-lived token

# Module-level cached client state (per Gunicorn worker process)
# WHY cache? Vault login creates a token — unnecessary logins waste Vault capacity.
# WHY per-process? Gunicorn forks workers; each worker gets its own cache.
_vault_client: hvac.Client | None = None
_token_expiry: float = 0.0
_client_lock = threading.Lock()   # guards renewal in threaded workers


def _read_secret_file(env_var: str, fallback_path: str) -> str:
    """
    Read a credential from a Docker secret file.
    Path comes from env var (set in docker-compose) or falls back to default.
    """
    path = os.environ.get(env_var, fallback_path)
    try:
        with open(path, encoding='utf-8') as f:
            value = f.read().strip()
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"Required secret file not found: {path} (env: {env_var}). "
            "Run init-vault.sh first, then restart containers."
        ) from exc

    if not value:
        raise RuntimeError(f"Required secret file is empty: {path} (env: {env_var})")

    return value


def _get_vault_client() -> hvac.Client:
    """
    Return an authenticated Vault client, re-authenticating via AppRole when
    the current token has less than 20% of its TTL remaining.

    WHY 20% renewal buffer?
    Renewing at 0% risks a race condition where the token expires between
    the TTL check and the next API call. 20% gives a safe window.
    """
    global _vault_client, _token_expiry

    now = time.time()
    # Fast path — token still has > 20% TTL left, no lock needed
    if _vault_client is not None and now < _token_expiry:
        return _vault_client

    with _client_lock:
        # Re-check inside lock (another thread may have renewed already)
        now = time.time()
        if _vault_client is not None and now < _token_expiry:
            return _vault_client

        logger.info("Authenticating with Vault via AppRole...")

        role_id   = _read_secret_file('VAULT_ROLE_ID_FILE',   '/run/secrets/vault_role_id')
        secret_id = _read_secret_file('VAULT_SECRET_ID_FILE', '/run/secrets/vault_secret_id')

        client = hvac.Client(url=os.environ.get('VAULT_ADDR', 'http://vault:8200'))

        try:
            login_response = client.auth.approle.login(
                role_id=role_id,
                secret_id=secret_id
            )
        except hvac.exceptions.InvalidRequest as e:
            raise RuntimeError(
                f"AppRole login failed - invalid role_id or secret_id: {e}. "
                "Has init-vault.sh been run? Has the secret_id expired (24h TTL)?"
            ) from e
        except hvac.exceptions.VaultDown as e:
            raise RuntimeError(
                "Vault is sealed or unreachable. "
                "Run: docker exec zt-vault vault operator unseal"
            ) from e

        # Parse the token TTL from the login response
        # token_ttl is in seconds (e.g. 3600 for 1h)
        client.token = login_response['auth']['client_token']
        token_ttl = int(login_response['auth']['lease_duration'])
        if token_ttl <= 0:
            raise RuntimeError("Vault AppRole login returned a non-expiring or invalid token TTL")

        # Renew at 80% of TTL elapsed (= 20% remaining)
        _token_expiry  = time.time() + (token_ttl * 0.8)
        _vault_client  = client

        logger.info(f"Vault AppRole login successful. Token valid for {token_ttl}s, renewing at {int(token_ttl * 0.8)}s.")
        return _vault_client


def _read_vault_secret(path: str) -> str:
    """
    Read a static secret from Vault KV v2.

    WHY mount_point='secret'?
    init-vault.sh enables: vault secrets enable -path=secret kv-v2
    API path: /v1/secret/data/<path>

    WHY key 'value'?
    init-vault.sh stores all secrets with field name 'value':
        vault kv put secret/redis/password value="$REDIS_PASSWORD"
    """
    client = _get_vault_client()
    try:
        secret = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point='secret',
            raise_on_deleted_version=True
        )
        return secret['data']['data']['value']
    except KeyError as exc:
        raise RuntimeError(f"Vault secret secret/{path} is missing required field 'value'") from exc


def _get_vault_db_credentials() -> dict:
    """
    Get dynamic (rotating) PostgreSQL credentials from Vault.
    Each call creates a unique temporary DB user expiring after 24h.
    """
    client = _get_vault_client()
    creds = client.secrets.database.generate_credentials(name='app-role')
    return creds['data']


# ==============================================================================
# APP INITIALIZATION
# ==============================================================================
app = Flask(__name__)

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config['DEBUG'] = False
app.config['TESTING'] = False
app.config['PROPAGATE_EXCEPTIONS'] = False

# SECRET_KEY: env var set in docker-compose takes priority.
# Only calls Vault if env var is genuinely absent (not just empty).
_secret_key = os.environ.get('SECRET_KEY')
app.config['SECRET_KEY'] = (
    _secret_key if _secret_key is not None
    else _read_vault_secret('app/session_key')
)
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY is empty")

# Redis password: same env-var-first pattern.
# WHY no hardcoded fallback?
# A hardcoded fallback gets committed to git and may silently reach production.
# Fail loudly instead of silently using a weak credential.
_redis_pw = os.environ.get('REDIS_PASSWORD')
if not _redis_pw:
    _redis_pw = _read_vault_secret('redis/password')
if not _redis_pw:
    raise RuntimeError("Redis password is empty")

redis_host = os.environ.get('REDIS_HOST', 'redis')
redis_port = os.environ.get('REDIS_PORT', '6379')
redis_password = quote(_redis_pw, safe='')

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri=f"redis://:{redis_password}@{redis_host}:{redis_port}/0",
    default_limits=["200 per day", "50 per hour"],
    strategy="fixed-window"
)


# ==============================================================================
# DATABASE CONNECTION
# ==============================================================================
def get_db():
    if 'db' not in g:
        creds = _get_vault_db_credentials()
        g.db = psycopg2.connect(
            host=os.environ.get('POSTGRES_HOST', 'postgres_primary'),
            port=int(os.environ.get('POSTGRES_PORT', '5432')),
            database=os.environ.get('POSTGRES_DB', 'appdb'),
            user=creds['username'],
            password=creds['password'],
            sslmode=os.environ.get('POSTGRES_SSLMODE', 'require'),
            connect_timeout=5
        )
        g.db.autocommit = False
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        try:
            db.rollback()
        except Exception:
            pass
        db.close()


# ==============================================================================
# HEALTH CHECK
# ==============================================================================
@app.route('/health')
def health():
    checks = {}
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute("SELECT 1")
        checks['database'] = 'ok'
    except Exception as e:
        logger.error(f"Health check DB failed: {e}")
        checks['database'] = 'error'

    status = 200 if all(v == 'ok' for v in checks.values()) else 503
    return jsonify({'status': 'healthy' if status == 200 else 'degraded', 'checks': checks}), status


# ==============================================================================
# USER REGISTRATION
# ==============================================================================
@app.route('/api/users/register', methods=['POST'])
@limiter.limit("5 per minute")
def register_user():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({'error': 'Request body must be valid JSON'}), 400

    try:
        sanitizer = InputSanitizer()
        clean = {
            'username': sanitizer.username(data.get('username', '')),
            'email':    sanitizer.email(data.get('email', '')),
            'password': sanitizer.password(data.get('password', '')),
        }
    except SanitizationError as e:
        logger.warning(f"Registration validation failed: {e} | IP: {request.remote_addr}")
        return jsonify({'error': 'Invalid input'}), 422

    password_hash = bcrypt.hashpw(
        clean['password'].encode('utf-8'),
        bcrypt.gensalt(rounds=12)
    )

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (username, email, password_hash, created_at)
                VALUES (%s, %s, %s, NOW())
                RETURNING id
                """,
                (clean['username'], clean['email'], password_hash.decode('utf-8'))
            )
            row = cur.fetchone()
            if row is None:
                raise Exception('Failed to retrieve user id after insert')
            user_id = row[0]
        db.commit()
        logger.info(f"User registered: id={user_id}")
        return jsonify({'message': 'User created', 'id': user_id}), 201

    except psycopg2.IntegrityError:
        db.rollback()
        return jsonify({'error': 'Registration failed'}), 409
    except Exception as e:
        db.rollback()
        logger.error(f"Registration DB error: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# ==============================================================================
# SEARCH ENDPOINT
# ==============================================================================
@app.route('/api/search')
@limiter.limit("30 per minute")
def search():
    try:
        sanitizer = InputSanitizer()
        term     = sanitizer.search_term(request.args.get('q', ''))
        page     = sanitizer.positive_integer(request.args.get('page', '1'), max_val=1000)
        per_page = sanitizer.positive_integer(request.args.get('per_page', '20'), max_val=100)
    except SanitizationError as e:
        return jsonify({'error': str(e)}), 422

    offset = (page - 1) * per_page
    try:
        db = get_db()
        with db.cursor() as cur:
            cur.execute(
                "SELECT id, name, description FROM items WHERE name ILIKE %s LIMIT %s OFFSET %s",
                (f'%{term}%', per_page, offset)
            )
            results = [{'id': r[0], 'name': r[1], 'description': r[2]} for r in cur.fetchall()]
    except Exception as e:
        logger.error(f"Search DB error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

    return jsonify({'results': results, 'page': page, 'per_page': per_page})


# ==============================================================================
# GLOBAL ERROR HANDLERS
# ==============================================================================
@app.errorhandler(400)
def bad_request(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'error': 'Method not allowed'}), 405

@app.errorhandler(429)
def ratelimit_exceeded(e):
    logger.warning(f"Rate limit exceeded: IP={request.remote_addr}")
    return jsonify({'error': 'Too many requests', 'retry_after': e.description}), 429

@app.errorhandler(500)
def server_error(e):
    logger.error(f"Unhandled 500: {e}", exc_info=True)
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
