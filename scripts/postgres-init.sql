CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(32) NOT NULL UNIQUE,
    email VARCHAR(254) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS items (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_items_name ON items (name);

INSERT INTO items (name, description)
VALUES
    ('Zero Trust', 'Never trust, always verify.'),
    ('Vault AppRole', 'Machine authentication with short-lived Vault tokens.'),
    ('Dynamic Database Credentials', 'Temporary PostgreSQL users issued by Vault.')
ON CONFLICT DO NOTHING;
