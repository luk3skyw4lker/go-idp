# Local Go IdP (OIDC/OAuth2 + SAML) - Fiber + Postgres

This is a local/test Identity Provider (IdP) written in Go. It provides:

- **OIDC/OAuth2 (testing-focused)**:
  - Authorization Code + **PKCE** (`/authorize`, `/token`)
  - OAuth2 **Resource Owner Password** grant (`/token` with `grant_type=password`)
  - OIDC discovery (`/.well-known/openid-configuration`)
  - JWKS (`/jwks`)
  - `/userinfo`
- **SAML 2.0 (SP-initiated HTTP-POST)**:
  - IdP metadata (`/saml/metadata`)
  - SP-initiated SSO endpoint (`/saml/sso`) that returns an auto-submitting HTML form containing `SAMLResponse`
- **Persistent sessions** backed by **Postgres**, stored in an `HttpOnly` cookie.

HTTP server: **Fiber** (`github.com/gofiber/fiber/v3`).

## Endpoints

Health

- `GET /healthz` -> `200 ok`

Login UI

- `GET /login` -> HTML login form
- `POST /login` -> verifies credentials and creates a session
  - If the request includes `pending_id` or `pending_saml_id`, login will resume the corresponding OAuth2/OIDC or SAML flow.

OIDC / OAuth2

- `GET /.well-known/openid-configuration` -> JSON discovery document
- `GET /jwks` -> JSON Web Key Set (RSA public keys)
- `GET /authorize` -> Authorization Code + PKCE authorization endpoint
- `POST /token` -> token endpoint (supports `authorization_code` and `password` grants)
- `GET /userinfo` -> user claims (session required)

SAML (SP-initiated)

- `GET /saml/metadata` -> SAML IdP metadata (includes signing cert)
- `POST /saml/sso` -> consumes `SAMLRequest` (and optional `RelayState`)
  - If the browser is not logged in, it redirects to `/login` and stores pending SAML state.
- `GET /saml/sso?pending_saml_id=...` -> resumes pending SAML flow and returns HTML auto-submit form

## Sessions and Cookies

- Cookie name: `idp_session`
- Cookie attributes: `HttpOnly`, `Path=/`, `SameSite=Lax`
- Session lookup is performed by middleware; endpoints rely on `GET /userinfo` requiring a valid session.

## Configuration

The IdP and `idpctl` support either:

- root-level `config.yml` / `config.yaml`
- environment variables (env values override YAML values)

Example `config.yml`:

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

Required

- `DATABASE_URL` - Postgres connection string
- `PUBLIC_ISSUER_URL` - public issuer URL (used in OIDC discovery and token `iss`)

Optional

- `LISTEN_ADDR` (default `:8080`)
- `COOKIE_SECURE` (default `false`)
- `SESSION_TTL` (default `24h`)
- `JWT_ACCESS_TTL` (default `15m`)
- `JWT_ID_TTL` (default `15m`)
- `DEV_KEYS_DIR` (default `./dev-keys`)
  - RSA keys for JWT/JWKS are persisted as PEM files under this directory.
- `MIGRATIONS_DIR` (default `./migrations`)
  - Directory containing SQL migrations in Goose format.

## Build / Run

## Docker Compose (Full Local Stack)

This repository includes a full Docker Compose stack that starts:

- `db` (Postgres 16)
- `idp-bootstrap` (one-shot migration + seeding job via `idpctl`)
- `idp` (Fiber server)

### Start everything

```bash
docker compose up --build
```

IdP endpoints will be available at `http://localhost:8080`.

### Seeded defaults

Compose bootstrap seeds:

- User: `alice` / `password123`
- OAuth2/OIDC client:
  - `client_id`: `demo-client`
  - **public client** (`--public`): no `client_secret` (suitable for local dev / PKCE)
  - redirect URI: `http://localhost:8081/callback`
  - grant types: `authorization_code,password`
  - scopes: `openid`
- SAML SP:
  - issuer: `http://sp.example/metadata`
  - ACS URL: `http://sp.example/acs`
  - audience: `http://sp.example/audience`

### Quick smoke checks

```bash
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/.well-known/openid-configuration
curl -sS http://localhost:8080/jwks
curl -sS http://localhost:8080/saml/metadata
```

### Stop / reset

Stop services:

```bash
docker compose down
```

Stop and remove DB/dev-key volumes (full reset):

```bash
docker compose down -v
```

### 1) Start Postgres

Example (Docker):

```bash
docker run --rm -it \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=postgres \
  -p 5432:5432 \
  postgres:16
```

### 2) Set environment variables

Example:

```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
export PUBLIC_ISSUER_URL="http://localhost:8080"
export LISTEN_ADDR=":8080"
```

### 3) Run the IdP server

It will run Goose migrations automatically on startup.

```bash
go run ./cmd/idp
```

## Seeding Data (users, OAuth2/OIDC clients, SAML SPs)

Seeding is done via the CLI tool `cmd/idpctl` (which also runs Goose migrations).

Build/run options:

- Use `go run ./cmd/idpctl ...` while iterating
- Or `go build -o idpctl ./cmd/idpctl` and run the resulting binary
- Install globally from current source checkout:
  - `go install ./cmd/idpctl`
- Install from GitHub:
  - `go install github.com/luk3skyw4lker/go-idp/cmd/idpctl@latest`
  - if your public repo path is different, update this path to match your `module` line in `go.mod`

After install, ensure your Go bin directory is in `PATH`:

```bash
export PATH="$(go env GOPATH)/bin:$PATH"
```

### Add a local user

```bash
go run ./cmd/idpctl user add \
  --username alice \
  --password password123 \
  --display-name "Alice Example" \
  --email alice@example.com
```

### Add an OAuth2/OIDC client

This IdP enforces:

- `redirect_uri` must be present in the client's stored `redirect_uris`
- `scope` must be within the client's `allowed_scopes`
- for OIDC `id_token`, `openid` scope requires a `nonce` parameter
- if the client has a **stored secret** (confidential client), `POST /token` must include a matching `client_secret`

**Confidential client** (default): `idpctl` generates a random `client_secret`, bcrypt-hashes it, stores the hash, and prints the plain secret once (save it).

After `client add`, `idpctl` prints an OIDC/OAuth2 integration config block (issuer/endpoints, client id, auth method, grants/scopes, and secret details).

```bash
go run ./cmd/idpctl client add \
  --client-id my-app \
  --redirect-uri "http://localhost:8081/callback" \
  --grant-types "authorization_code,password" \
  --scopes "openid"
# copy client_secret=... from the output; use it on /token as client_secret
```

**Public client** (no secret, e.g. dev / browser-only PKCE):

```bash
go run ./cmd/idpctl client add \
  --public \
  --client-id demo-client \
  --redirect-uri "http://localhost:8081/callback" \
  --grant-types "authorization_code,password" \
  --scopes "openid"
```

Optional: `--client-secret <value>` hashes a secret you choose instead of generating one (cannot be used with `--public`).

Repeat `--redirect-uri` multiple times for multiple allowed redirect URIs.

### Add a SAML SP registry entry

This IdP supports SP-initiated HTTP-POST SSO.

After `samlsp add`, `idpctl` prints a SAML integration config block (IdP metadata/SSO URLs plus SP entity/ACS/audience values).

```bash
go run ./cmd/idpctl samlsp add \
  --issuer "http://sp.example/metadata" \
  --acs-url "http://sp.example/acs" \
  --audience-uri "http://sp.example/audience" \
  --name-id-format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
```

Notes:

- `issuer` is the SP EntityID (must match `Issuer` found inside the incoming `SAMLRequest`)
- `acs-url` is used as the `Destination` and as the `action` in the returned HTML form

## Integrate with Your Local App (SSO Testing)

Use this section when you want your own local app (frontend/backend) to use this IdP for sign-in testing.

### OIDC (recommended for modern apps)

1. Register your app callback URL in the IdP client:

```bash
go run ./cmd/idpctl client add \
  --public \
  --client-id my-local-app \
  --redirect-uri "http://localhost:3000/auth/callback" \
  --grant-types "authorization_code" \
  --scopes "openid"
```

2. Configure your app's OIDC settings:

- issuer: `http://localhost:8080`
- authorization endpoint: `http://localhost:8080/authorize`
- token endpoint: `http://localhost:8080/token`
- jwks uri: `http://localhost:8080/jwks`
- client id: `my-local-app`
- redirect uri: `http://localhost:3000/auth/callback`
- scopes: `openid`
- response type: `code`
- PKCE: `S256` enabled
- send `nonce` when requesting `openid`

3. Start login from your app by redirecting users to `/authorize` with:

- `response_type=code`
- `client_id=my-local-app`
- `redirect_uri=http://localhost:3000/auth/callback`
- `scope=openid`
- `state=<random>`
- `code_challenge=<pkce challenge>`
- `code_challenge_method=S256`
- `nonce=<random>`

4. Handle callback in your app:

- read `code` and `state`
- verify `state`
- call `POST /token` with:
  - `grant_type=authorization_code`
  - `code`
  - `code_verifier`
  - `client_id=my-local-app`
  - `redirect_uri=http://localhost:3000/auth/callback`
- store/validate returned tokens as needed in your app

### SAML (SP-initiated testing)

1. Register your local SP values:

```bash
go run ./cmd/idpctl samlsp add \
  --issuer "http://localhost:3000/saml/metadata" \
  --acs-url "http://localhost:3000/saml/acs" \
  --audience-uri "http://localhost:3000/saml/audience" \
  --name-id-format "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
```

2. Configure your app/SP:

- IdP metadata URL: `http://localhost:8080/saml/metadata`
- IdP SSO URL: `http://localhost:8080/saml/sso`
- SP EntityID/Issuer: must match the `--issuer` value you registered
- ACS URL: must match the `--acs-url` value you registered

3. Trigger SP-initiated login from your app:

- your app creates `AuthnRequest`
- your app sends `SAMLRequest` to `POST http://localhost:8080/saml/sso`
- IdP returns an auto-submitting HTML form containing `SAMLResponse` to your ACS URL

### Local dev tips

- Keep all app URLs on `localhost` to avoid cookie/domain surprises.
- If login/session behavior looks stale, reset with `docker compose down -v` and restart.
- For browser-based OIDC testing, use an app callback page that can log query params (`code`, `state`) for debugging.

## OIDC / OAuth2 Authorization Code + PKCE (happy path)

High-level flow:

1. Call `GET /authorize` with PKCE + `nonce`
2. If not logged in, IdP redirects you to `POST /login` (with `pending_id`)
3. After login, IdP redirects to your `redirect_uri` with `code` + `state`
4. Call `POST /token` with `grant_type=authorization_code`, `code`, and `code_verifier`
5. If `scope` includes `openid`, the response includes a signed `id_token`

### Required parameters for `/authorize`

- `response_type=code`
- `client_id`
- `redirect_uri`
- `scope` (request `openid` for `id_token`)
- `state`
- `code_challenge` + `code_challenge_method=S256`
- `nonce` is required when `scope` includes `openid`

### `/token` for PKCE

- `grant_type=authorization_code`
- `code`
- `code_verifier` (must match the `S256` code challenge)
- `client_id`
- `redirect_uri`

### Token response fields

- `access_token`
- `token_type` (Bearer)
- `expires_in`
- `id_token` (only when `openid` is in scope)

## OAuth2 Password Grant (testing)

High-level:

1. `POST /token` with `grant_type=password`
2. Supply `username` + `password` + `client_id`
3. Optionally request `scope=openid` when you want an `id_token`
4. If `openid` is requested, `nonce` is required

Required fields for `grant_type=password`:

- `username`
- `password`
- `client_id`
- optionally `scope`
- `nonce` is required when using `openid`

Notes:

- Empty/omitted `scope` does **not** implicitly request `openid`.
- `id_token` is only returned when `scope` includes `openid` and a `nonce` is provided.

Example (access token only):

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=demo-client&username=alice&password=password123"
```

Example (OIDC token response with `id_token`):

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&client_id=demo-client&username=alice&password=password123&scope=openid&nonce=demo-nonce"
```

## SAML SP-initiated HTTP-POST flow (testing)

High-level flow:

1. POST `SAMLRequest` (base64-encoded XML) to `POST /saml/sso`
2. If not logged in, IdP persists pending state and redirects to `/login` with `pending_saml_id`
3. After login, call `GET /saml/sso?pending_saml_id=...`
4. The response is HTML that auto-submits a form containing `SAMLResponse` to the SP ACS URL.

### Sending `SAMLRequest`

- Endpoint: `POST /saml/sso`
- Form params:
  - `SAMLRequest` (base64 of the XML payload)
  - `RelayState` (optional)

### Getting the SAMLResponse

- After login, resume:
  - `GET /saml/sso?pending_saml_id=...`
- Response:
  - `200` with `text/html`
  - contains hidden input `name="SAMLResponse"` and JS auto-submit

## Development Notes

- JWT signing keys for OIDC/JWKS:
  - generated on first run and persisted under `DEV_KEYS_DIR`
  - active key metadata is stored in Postgres (`signing_keys_meta`)
- SAML signing keys:
  - currently generated for the running process (metadata and signatures are consistent within that process)
- Migrations:
  - migrations are executed automatically on IdP startup and by `idpctl`

## Integration Tests

There are end-to-end tests under `internal/integration/`.

They require at least:

- `DATABASE_URL`
- `PUBLIC_ISSUER_URL`

Run:

```bash
go test ./... -run TestOIDC_AuthorizationCode_PKCE -v
go test ./... -run TestSAML_SPInitiated_POST -v
```
