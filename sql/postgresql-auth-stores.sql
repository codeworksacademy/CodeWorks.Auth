-- PostgreSQL schema for CodeWorks.Auth DB-backed stores

CREATE TABLE auth_refresh_tokens (
  token_hash VARCHAR(200) PRIMARY KEY,
  user_id VARCHAR(200) NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ NULL,
  replaced_by_token_hash VARCHAR(200) NULL
);

CREATE INDEX ix_auth_refresh_tokens_user_id ON auth_refresh_tokens (user_id);
CREATE INDEX ix_auth_refresh_tokens_expires_at ON auth_refresh_tokens (expires_at);

CREATE TABLE auth_passkey_challenges (
  challenge VARCHAR(200) PRIMARY KEY,
  user_id VARCHAR(200) NULL,
  purpose INTEGER NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX ix_auth_passkey_challenges_expires_at ON auth_passkey_challenges (expires_at);

CREATE TABLE auth_passkey_credentials (
  credential_id VARCHAR(256) PRIMARY KEY,
  user_id VARCHAR(200) NOT NULL,
  public_key TEXT NOT NULL,
  sign_count BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  last_used_at TIMESTAMPTZ NULL
);

CREATE INDEX ix_auth_passkey_credentials_user_id ON auth_passkey_credentials (user_id);
