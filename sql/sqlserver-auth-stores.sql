-- SQL Server schema for CodeWorks.Auth DB-backed stores

CREATE TABLE auth_refresh_tokens (
  token_hash NVARCHAR(200) NOT NULL PRIMARY KEY,
  user_id NVARCHAR(200) NOT NULL,
  created_at DATETIME2 NOT NULL,
  expires_at DATETIME2 NOT NULL,
  revoked_at DATETIME2 NULL,
  replaced_by_token_hash NVARCHAR(200) NULL
);

CREATE INDEX ix_auth_refresh_tokens_user_id ON auth_refresh_tokens (user_id);
CREATE INDEX ix_auth_refresh_tokens_expires_at ON auth_refresh_tokens (expires_at);

CREATE TABLE auth_passkey_challenges (
  challenge NVARCHAR(200) NOT NULL PRIMARY KEY,
  user_id NVARCHAR(200) NULL,
  purpose INT NOT NULL,
  created_at DATETIME2 NOT NULL,
  expires_at DATETIME2 NOT NULL
);

CREATE INDEX ix_auth_passkey_challenges_expires_at ON auth_passkey_challenges (expires_at);

CREATE TABLE auth_passkey_credentials (
  credential_id NVARCHAR(256) NOT NULL PRIMARY KEY,
  user_id NVARCHAR(200) NOT NULL,
  public_key NVARCHAR(MAX) NOT NULL,
  sign_count BIGINT NOT NULL,
  created_at DATETIME2 NOT NULL,
  last_used_at DATETIME2 NULL
);

CREATE INDEX ix_auth_passkey_credentials_user_id ON auth_passkey_credentials (user_id);
