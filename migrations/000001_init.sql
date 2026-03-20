-- +goose Up
-- Basic schema for local IdP testing.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username text NOT NULL UNIQUE,
  password_hash text NOT NULL,
  display_name text,
  email text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS clients (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id text NOT NULL UNIQUE,
  client_secret_hash text,
  redirect_uris text NOT NULL DEFAULT '[]',
  token_endpoint_auth_method text NOT NULL DEFAULT 'none',
  allowed_grant_types text[] NOT NULL DEFAULT ARRAY['authorization_code'],
  allowed_scopes text[] NOT NULL DEFAULT ARRAY['openid'],
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code text PRIMARY KEY,
  client_id text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
  redirect_uri text NOT NULL,
  code_challenge text NOT NULL,
  code_challenge_method text NOT NULL DEFAULT 'S256',
  scope text,
  nonce text,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz
);

CREATE INDEX IF NOT EXISTS authorization_codes_expires_at_idx
  ON authorization_codes (expires_at);

CREATE TABLE IF NOT EXISTS sessions (
  session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS signing_keys_meta (
  kid text PRIMARY KEY,
  active boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  private_pem_path text NOT NULL,
  public_pem_path text NOT NULL
);

-- Only one active key at a time (enforced by application logic for now).
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_meta_active_unique
  ON signing_keys_meta (active)
  WHERE active = true;

CREATE TABLE IF NOT EXISTS pending_auth_requests (
  pending_id text PRIMARY KEY,
  client_id text NOT NULL,
  redirect_uri text NOT NULL,
  state text NOT NULL,
  code_challenge text NOT NULL,
  code_challenge_method text NOT NULL DEFAULT 'S256',
  scope text,
  nonce text,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS pending_auth_requests_expires_at_idx ON pending_auth_requests (expires_at);

CREATE TABLE IF NOT EXISTS saml_sp_registry (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  issuer text NOT NULL UNIQUE, -- SP EntityID
  acs_url text NOT NULL,
  audience_uri text,
  name_id_format text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pending_saml_requests (
  pending_id text PRIMARY KEY,
  sp_issuer text NOT NULL REFERENCES saml_sp_registry(issuer) ON DELETE CASCADE,
  relay_state text,
  saml_request_xml text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS pending_saml_requests_expires_at_idx
  ON pending_saml_requests (expires_at);

-- +goose Down

DROP TABLE IF EXISTS pending_saml_requests;
DROP TABLE IF EXISTS saml_sp_registry;
DROP TABLE IF EXISTS pending_auth_requests;
DROP TABLE IF EXISTS signing_keys_meta;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS users;

