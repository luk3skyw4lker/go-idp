package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("not found")

type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash, displayName, email string) (User, error) {
	var u User
	err := s.pool.QueryRow(
		ctx,
		`INSERT INTO users (username, password_hash, display_name, email)
		 VALUES ($1,$2,$3,$4)
		 RETURNING id, username, password_hash, display_name, email, created_at`,
		username, passwordHash, displayName, email,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &u.CreatedAt)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) GetUserByID(ctx context.Context, id string) (User, error) {
	var u User
	err := s.pool.QueryRow(
		ctx,
		`SELECT id, username, password_hash, display_name, email, created_at
		 FROM users
		 WHERE id=$1`,
		id,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &u.CreatedAt)

	return u, err
}

func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	var u User
	err := s.pool.QueryRow(
		ctx,
		`SELECT id, username, password_hash, display_name, email, created_at
		 FROM users
		 WHERE username=$1`,
		username,
	).Scan(&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.Email, &u.CreatedAt)
	if err != nil {
		return User{}, err
	}
	return u, nil
}

func (s *Store) CreateSession(ctx context.Context, userID string, expiresAt time.Time) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(
		ctx,
		`INSERT INTO sessions (user_id, expires_at)
		 VALUES ($1,$2)
		 RETURNING session_id, user_id, expires_at, last_seen_at`,
		userID, expiresAt,
	).Scan(&sess.SessionID, &sess.UserID, &sess.ExpiresAt, &sess.LastSeenAt)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

func (s *Store) GetSession(ctx context.Context, sessionID string) (Session, error) {
	var sess Session
	err := s.pool.QueryRow(
		ctx,
		`SELECT session_id, user_id, expires_at, last_seen_at
		 FROM sessions
		 WHERE session_id=$1 AND expires_at > now()`,
		sessionID,
	).Scan(&sess.SessionID, &sess.UserID, &sess.ExpiresAt, &sess.LastSeenAt)
	if err != nil {
		return Session{}, err
	}
	return sess, nil
}

func (s *Store) UpdateSessionLastSeen(ctx context.Context, sessionID string) error {
	_, err := s.pool.Exec(ctx, `UPDATE sessions SET last_seen_at=now() WHERE session_id=$1`, sessionID)
	return err
}

type SigningKeyMeta struct {
	Kid            string
	PrivatePemPath string
	PublicPemPath  string
	Active         bool
	CreatedAt      time.Time
}

func (s *Store) GetActiveSigningKey(ctx context.Context) (SigningKeyMeta, error) {
	var k SigningKeyMeta
	err := s.pool.QueryRow(
		ctx,
		`SELECT kid, active, created_at, private_pem_path, public_pem_path
		 FROM signing_keys_meta
		 WHERE active = true
		 LIMIT 1`,
	).Scan(&k.Kid, &k.Active, &k.CreatedAt, &k.PrivatePemPath, &k.PublicPemPath)
	if err != nil {
		return SigningKeyMeta{}, err
	}
	return k, nil
}

func (s *Store) SetActiveSigningKey(ctx context.Context, kid string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `UPDATE signing_keys_meta SET active=false WHERE active=true`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE signing_keys_meta SET active=true WHERE kid=$1`, kid); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) CreateSigningKeyMeta(ctx context.Context, meta SigningKeyMeta) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO signing_keys_meta (kid, active, private_pem_path, public_pem_path)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (kid)
		 DO UPDATE SET
		   active=EXCLUDED.active,
		   private_pem_path=EXCLUDED.private_pem_path,
		   public_pem_path=EXCLUDED.public_pem_path,
		   created_at=signing_keys_meta.created_at`,
		meta.Kid, meta.Active, meta.PrivatePemPath, meta.PublicPemPath,
	)
	return err
}

type PendingAuthRequest struct {
	PendingID           string
	ClientID            string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	ExpiresAt           time.Time
}

func (s *Store) PutPendingAuthRequest(ctx context.Context, req PendingAuthRequest) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO pending_auth_requests
		 (pending_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, nonce, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		req.PendingID, req.ClientID, req.RedirectURI, req.State, req.CodeChallenge, req.CodeChallengeMethod,
		req.Scope, req.Nonce, req.ExpiresAt,
	)
	return err
}

func (s *Store) ConsumePendingAuthRequest(ctx context.Context, pendingID string) (PendingAuthRequest, error) {
	var req PendingAuthRequest
	err := s.pool.QueryRow(
		ctx,
		`DELETE FROM pending_auth_requests
		 WHERE pending_id=$1
		 RETURNING pending_id, client_id, redirect_uri, state, code_challenge, code_challenge_method, scope, nonce, expires_at`,
		pendingID,
	).Scan(
		&req.PendingID, &req.ClientID, &req.RedirectURI, &req.State, &req.CodeChallenge, &req.CodeChallengeMethod,
		&req.Scope, &req.Nonce, &req.ExpiresAt,
	)
	if err != nil {
		return PendingAuthRequest{}, err
	}
	return req, nil
}

type AuthorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	Scope               string
	Nonce               string
	UserID              string
	ExpiresAt           time.Time
	UsedAt              *time.Time
}

func (s *Store) CreateAuthorizationCode(ctx context.Context, code AuthorizationCode) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO authorization_codes
		 (code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, nonce, user_id, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		code.Code, code.ClientID, code.RedirectURI, code.CodeChallenge, code.CodeChallengeMethod, code.Scope,
		code.Nonce, code.UserID, code.ExpiresAt,
	)
	return err
}

func (s *Store) ConsumeAuthorizationCode(ctx context.Context, code string) (AuthorizationCode, error) {
	var ac AuthorizationCode
	err := s.pool.QueryRow(
		ctx,
		`UPDATE authorization_codes
		 SET used_at=now()
		 WHERE code=$1 AND used_at IS NULL AND expires_at > now()
		 RETURNING code, client_id, redirect_uri, code_challenge, code_challenge_method, scope, nonce, user_id, expires_at, used_at`,
		code,
	).Scan(
		&ac.Code, &ac.ClientID, &ac.RedirectURI, &ac.CodeChallenge, &ac.CodeChallengeMethod,
		&ac.Scope, &ac.Nonce, &ac.UserID, &ac.ExpiresAt, &ac.UsedAt,
	)
	if err != nil {
		return AuthorizationCode{}, err
	}
	return ac, nil
}

func (s *Store) GetClientByClientID(ctx context.Context, clientID string) (Client, error) {
	var c Client
	err := s.pool.QueryRow(
		ctx,
		`SELECT client_id, client_secret_hash, redirect_uris, token_endpoint_auth_method,
		        allowed_grant_types, allowed_scopes
		 FROM clients
		 WHERE client_id=$1`,
		clientID,
	).Scan(&c.ClientID, &c.ClientSecretHash, &c.RedirectURIsJSON, &c.TokenEndpointAuthMethod, &c.AllowedGrantTypes, &c.AllowedScopes)
	if err != nil {
		return Client{}, err
	}
	return c, nil
}

func (s *Store) UpsertClient(ctx context.Context, c Client) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO clients
		 (client_id, client_secret_hash, redirect_uris, token_endpoint_auth_method, allowed_grant_types, allowed_scopes)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (client_id)
		 DO UPDATE SET
		   client_secret_hash=EXCLUDED.client_secret_hash,
		   redirect_uris=EXCLUDED.redirect_uris,
		   token_endpoint_auth_method=EXCLUDED.token_endpoint_auth_method,
		   allowed_grant_types=EXCLUDED.allowed_grant_types,
		   allowed_scopes=EXCLUDED.allowed_scopes`,
		c.ClientID,
		c.ClientSecretHash,
		c.RedirectURIsJSON,
		c.TokenEndpointAuthMethod,
		c.AllowedGrantTypes,
		c.AllowedScopes,
	)
	return err
}

type SamlSP struct {
	Issuer       string
	AcsURL       string
	AudienceURI  *string
	NameIDFormat *string
}

func (s *Store) GetSamlSPByIssuer(ctx context.Context, issuer string) (SamlSP, error) {
	var sp SamlSP
	err := s.pool.QueryRow(
		ctx,
		`SELECT issuer, acs_url, audience_uri, name_id_format
		 FROM saml_sp_registry
		 WHERE issuer=$1`,
		issuer,
	).Scan(&sp.Issuer, &sp.AcsURL, &sp.AudienceURI, &sp.NameIDFormat)
	if err != nil {
		return SamlSP{}, err
	}
	return sp, nil
}

func (s *Store) UpsertSamlSP(ctx context.Context, sp SamlSP) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO saml_sp_registry (issuer, acs_url, audience_uri, name_id_format)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (issuer)
		 DO UPDATE SET
		   acs_url=EXCLUDED.acs_url,
		   audience_uri=EXCLUDED.audience_uri,
		   name_id_format=EXCLUDED.name_id_format`,
		sp.Issuer,
		sp.AcsURL,
		sp.AudienceURI,
		sp.NameIDFormat,
	)
	return err
}

type PendingSamlRequest struct {
	PendingID      string
	SPIssuer       string
	RelayState     *string
	SAMLRequestXML string
	ExpiresAt      time.Time
}

func (s *Store) PutPendingSamlRequest(ctx context.Context, req PendingSamlRequest) error {
	_, err := s.pool.Exec(
		ctx,
		`INSERT INTO pending_saml_requests (pending_id, sp_issuer, relay_state, saml_request_xml, expires_at)
		 VALUES ($1,$2,$3,$4,$5)`,
		req.PendingID, req.SPIssuer, req.RelayState, req.SAMLRequestXML, req.ExpiresAt,
	)
	return err
}

func (s *Store) ConsumePendingSamlRequest(ctx context.Context, pendingID string) (PendingSamlRequest, error) {
	var req PendingSamlRequest
	err := s.pool.QueryRow(
		ctx,
		`DELETE FROM pending_saml_requests
		 WHERE pending_id=$1
		 RETURNING pending_id, sp_issuer, relay_state, saml_request_xml, expires_at`,
		pendingID,
	).Scan(&req.PendingID, &req.SPIssuer, &req.RelayState, &req.SAMLRequestXML, &req.ExpiresAt)
	if err != nil {
		return PendingSamlRequest{}, err
	}
	return req, nil
}
