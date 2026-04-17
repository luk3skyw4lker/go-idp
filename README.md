# GoIdP

<p align="center">
  <img src="./assets/goidp-icon.svg" alt="GoIdP icon" width="250" height="200" />
</p>

<p align="center">
  <a href="https://github.com/luk3skyw4lker/go-idp/actions/workflows/build-and-test.yml"><img src="https://github.com/luk3skyw4lker/go-idp/actions/workflows/build-and-test.yml/badge.svg" alt="Build and Test"></a>
</p>

<p align="center">
  <strong>Self-hosted identity for local and pre-prod environments.</strong><br/>
  Spin up OIDC/OAuth2 + SAML in minutes with a Go + Fiber + Postgres stack.
</p>

##

GoIdP is a developer-first Identity Provider built for teams that need realistic authentication flows without the enterprise setup tax.
Use it to test:

- OIDC Authorization Code + PKCE flows
- OAuth2 password grant in controlled environments
- SAML SP-initiated HTTP-POST SSO
- Session-based browser login experiences

## Why GoIdP

- **Fast to start**: one command with Docker Compose
- **Protocol complete for local dev**: OIDC, OAuth2, SAML in one service
- **Deterministic testing**: seeded users, clients, and SP entries
- **Simple to operate**: Postgres-backed sessions + built-in migrations
- **Go-native stack**: Fiber HTTP server and straightforward codebase

## Feature Snapshot

### OIDC / OAuth2

- Authorization endpoint: `GET /authorize`
- Token endpoint: `POST /token` (`authorization_code`, `password`)
- Discovery: `GET /.well-known/openid-configuration`
- JWKS: `GET /jwks`
- User profile: `GET /userinfo`

### SAML 2.0 (SP-initiated HTTP-POST)

- IdP metadata: `GET /saml/metadata`
- SSO entrypoint: `POST /saml/sso`
- Login-resume endpoint: `GET /saml/sso?pending_saml_id=...`

### Login and Sessions

- Branded login UI at `GET /login`
- Postgres-backed session store
- `HttpOnly` cookie with `SameSite=Lax`

## Quick Start (Recommended)

Run the full local stack:

```bash
docker compose up --build
```

This starts:

- `db` (Postgres 16)
- `idp-bootstrap` (migrations + seed data)
- `idp` (GoIdP server)
  GoIdP will be available at `http://localhost:8080`.

### Seeded Defaults

- User: `alice` / `password123`
- OAuth2/OIDC client:
  - `client_id`: `demo-client`
  - public client (no secret)
  - redirect URI: `http://localhost:8081/callback`
  - grant types: `authorization_code,password`
  - scopes: `openid`
- SAML SP:
  - issuer: `http://sp.example/metadata`
  - ACS URL: `http://sp.example/acs`
  - audience URI: `http://sp.example/audience`

### Smoke Checks

```bash
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
curl -sS http://localhost:8080/jwks
curl -sS http://localhost:8080/saml/metadata
```

Stop services:

```bash
docker compose down
```

Reset DB and key volumes:

```bash
docker compose down -v
```

## Configuration

GoIdP supports:

- `config.yml` / `config.yaml` at repo root
- environment variables (env overrides YAML)
  Example:

```yaml
database_url: 'postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable'
public_issuer_url: 'http://localhost:8080'
listen_addr: ':8080'
cookie_secure: false
session_ttl: '24h'
jwt_access_ttl: '15m'
jwt_id_ttl: '15m'
dev_keys_dir: './dev-keys'
migrations_dir: './migrations'
```

Required:

- `DATABASE_URL`
- `PUBLIC_ISSUER_URL`

Optional:

- `LISTEN_ADDR` (default `:8080`)
- `COOKIE_SECURE` (default `false`)
- `SESSION_TTL` (default `24h`)
- `JWT_ACCESS_TTL` (default `15m`)
- `JWT_ID_TTL` (default `15m`)
- `DEV_KEYS_DIR` (default `./dev-keys`)
- `MIGRATIONS_DIR` (default `./migrations`)

## Manual Local Run (Without Compose)

1. Start Postgres
2. Set `DATABASE_URL` and `PUBLIC_ISSUER_URL`
3. Run:

```bash
go run ./cmd/idp
```

Migrations run automatically on startup.

## Manage Test Data with `idpctl`

`idpctl` manages users, OAuth clients, and SAML SP registrations.
Install:

```bash
go install ./cmd/idpctl
```

Ensure Go bin is on `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

### Add a User

```bash
go run ./cmd/idpctl user add \
  --username alice \
  --password password123 \
  --display-name "Alice Example" \
  --email alice@example.com
```

### Add an OAuth2/OIDC Client

Public client:

```bash
go run ./cmd/idpctl client add \
  --public \
  --client-id demo-client \
  --redirect-uri "http://localhost:8081/callback" \
  --grant-types "authorization_code,password" \
  --scopes "openid"
```

Confidential client:

```bash
go run ./cmd/idpctl client add \
  --client-id my-app \
  --redirect-uri "http://localhost:8081/callback" \
  --grant-types "authorization_code,password" \
  --scopes "openid"
```

### Add a SAML SP Entry

```bash
go run ./cmd/idpctl samlsp add \
  --issuer "http://sp.example/metadata" \
  --acs-url "http://sp.example/acs" \
  --audience-uri "http://sp.example/audience" \
  --name-id-format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
```

## Integrate Your App

### OIDC (Recommended)

Typical flow:

1. Register your callback URI in GoIdP
2. Redirect users to `GET /authorize` with `code_challenge` and `nonce`
3. Handle callback with `code` + `state`
4. Exchange code at `POST /token` with `code_verifier`
   Minimum authorize params:

- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope` (`openid` for ID token)
- `state`
- `code_challenge`
- `code_challenge_method=S256`
- `nonce` (required with `openid`)

### SAML (SP-initiated)

1. Register SP issuer + ACS URL in GoIdP
2. SP sends `SAMLRequest` to `POST /saml/sso`
3. If user is not logged in, GoIdP redirects to `/login`
4. After login, GoIdP returns auto-submit HTML with `SAMLResponse` to ACS

## API Endpoints

Health:

- `GET /healthz`
  Login:
- `GET /login`
- `POST /login`
  OIDC/OAuth2:
- `GET /.well-known/openid-configuration`
- `GET /jwks`
- `GET /authorize`
- `POST /token`

## Development Notes

- OIDC signing keys are persisted under `DEV_KEYS_DIR`
- Key metadata is stored in Postgres (`signing_keys_meta`)
- Migrations run via both `idp` and `idpctl`
- Integration tests are under `internal/integration/`
  Run tests:

```bash
go test ./... -run TestOIDC_AuthorizationCode_PKCE -v
go test ./... -run TestSAML_SPInitiated_POST -v
```
