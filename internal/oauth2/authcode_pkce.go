package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

type Handlers struct {
	store oauthStore
	cfg   config.Config

	tokenIssuer interface {
		IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error)
		IssueAccessToken(ctx context.Context, userID string, audience string, scope string) (string, error)
	}

	PendingAuthTTL   time.Duration
	AuthorizationTTL time.Duration
}

type oauthStore interface {
	GetClientByClientID(ctx context.Context, clientID string) (postgres.Client, error)
	PutPendingAuthRequest(ctx context.Context, req postgres.PendingAuthRequest) error
	CreateAuthorizationCode(ctx context.Context, code postgres.AuthorizationCode) error
	ConsumeAuthorizationCode(ctx context.Context, code string) (postgres.AuthorizationCode, error)
	GetUserByUsername(ctx context.Context, username string) (postgres.User, error)
}

func NewHandlers(store oauthStore, cfg config.Config, tokenIssuer interface {
	IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error)
	IssueAccessToken(ctx context.Context, userID string, audience string, scope string) (string, error)
}) *Handlers {
	return &Handlers{
		store:            store,
		cfg:              cfg,
		tokenIssuer:      tokenIssuer,
		PendingAuthTTL:   10 * time.Minute,
		AuthorizationTTL: 10 * time.Minute,
	}
}

func (h *Handlers) Authorize(c fiber.Ctx) error {
	ctx := c

	responseType := c.Query("response_type")
	if responseType != "code" {
		return h.oauthError(c, fiber.StatusBadRequest, "unsupported_response_type", "unsupported response_type", "authorize_response_type_not_code")
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	scope := c.Query("scope")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	nonce := c.Query("nonce")

	if clientID == "" || redirectURI == "" || state == "" || scope == "" || codeChallenge == "" || codeChallengeMethod == "" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing required parameters", "authorize_missing_required_params")
	}
	if codeChallengeMethod != "S256" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "unsupported code_challenge_method", "authorize_pkce_method_not_s256")
	}

	// Validate client.
	client, err := h.store.GetClientByClientID(ctx, clientID)
	if err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_client", "invalid client_id", "authorize_client_not_found")
	}

	if !contains(client.AllowedGrantTypes, "authorization_code") {
		return h.oauthError(c, fiber.StatusBadRequest, "unauthorized_client", "grant not allowed", "authorize_grant_not_allowed")
	}

	requestScopes := splitScopes(scope)
	if len(requestScopes) == 0 {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_scope", "invalid scope", "authorize_scope_empty")
	}

	// For OIDC, `nonce` is required when `openid` is requested.
	if contains(requestScopes, "openid") && nonce == "" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing nonce for openid scope", "authorize_missing_nonce_for_openid")
	}

	if !scopesAllAllowed(requestScopes, client.AllowedScopes) {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_scope", "scope not allowed", "authorize_scope_not_allowed")
	}

	redirectURIs, err := parseRedirectURIs(client.RedirectURIsJSON)
	if err != nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "client redirect_uris invalid", "authorize_client_redirect_uris_parse_failed")
	}
	if !contains(redirectURIs, redirectURI) {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "redirect_uri not allowed", "authorize_redirect_uri_not_allowed")
	}

	// If not authenticated, create pending request and redirect to login.
	userID, ok := session.UserIDFromContext(c)
	if !ok || userID == "" {
		pendingID := randomToken(24)
		req := postgres.PendingAuthRequest{
			PendingID:           pendingID,
			ClientID:            clientID,
			RedirectURI:         redirectURI,
			State:               state,
			CodeChallenge:       codeChallenge,
			CodeChallengeMethod: codeChallengeMethod,
			Scope:               strings.Join(requestScopes, " "),
			Nonce:               nonce,
			ExpiresAt:           time.Now().Add(h.PendingAuthTTL),
		}

		if err := h.store.PutPendingAuthRequest(ctx, req); err != nil {
			return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to persist pending auth request", "authorize_pending_auth_store_failed")
		}

		slog.Info("authorize_requires_login",
			"request_id", requestid.FromContext(c),
			"client_id", clientID,
			"pending_id", pendingID,
		)
		return c.Redirect().To(fmt.Sprintf("/login?pending_id=%s", url.QueryEscape(pendingID)))
	}

	// Authenticated: mint authorization code immediately.
	code := randomToken(32)
	authCode := postgres.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scope:               strings.Join(requestScopes, " "),
		Nonce:               nonce,
		UserID:              userID,
		ExpiresAt:           time.Now().Add(h.AuthorizationTTL),
	}
	if err := h.store.CreateAuthorizationCode(ctx, authCode); err != nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to create authorization code", "authorize_code_create_failed")
	}

	slog.Info("authorize_code_issued",
		"request_id", requestid.FromContext(c),
		"client_id", clientID,
		"redirect_uri", redirectURI,
		"scope", authCode.Scope,
		"nonce_present", nonce != "",
	)
	return c.Redirect().To(redirectWithCode(redirectURI, code, state))
}

func (h *Handlers) Token(c fiber.Ctx) error {
	grantType := c.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		return h.tokenAuthorizationCode(c)
	case "password":
		return h.tokenPassword(c)
	default:
		return h.oauthError(c, fiber.StatusBadRequest, "unsupported_grant_type", "unsupported grant_type", "token_unsupported_grant_type")
	}
}

func (h *Handlers) tokenAuthorizationCode(c fiber.Ctx) error {
	ctx := c

	code := c.FormValue("code")
	codeVerifier := c.FormValue("code_verifier")
	clientID := c.FormValue("client_id")
	redirectURI := c.FormValue("redirect_uri")
	if code == "" || codeVerifier == "" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing code or code_verifier", "token_code_or_verifier_missing")
	}

	authCode, err := h.store.ConsumeAuthorizationCode(ctx, code)
	if err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_grant", "invalid/expired authorization code", "token_auth_code_invalid_or_used_or_expired")
	}

	// Client + redirect_uri binding.
	if clientID != "" && authCode.ClientID != clientID {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_grant", "invalid client_id for code", "token_code_client_id_mismatch")
	}
	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_grant", "invalid redirect_uri for code", "token_code_redirect_uri_mismatch")
	}

	if authCode.CodeChallengeMethod != "S256" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "unsupported PKCE method", "token_pkce_method_not_s256")
	}

	expected := pkceS256(codeVerifier)
	if expected != authCode.CodeChallenge {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_grant", "invalid code_verifier", "token_pkce_verifier_mismatch")
	}

	client, err := h.store.GetClientByClientID(ctx, authCode.ClientID)
	if err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_client", "invalid client_id", "token_client_not_found_for_code")
	}
	if err := h.requireClientSecret(c, client); err != nil {
		return err
	}

	if h.tokenIssuer == nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "token issuer not configured", "token_access_issuer_nil")
	}
	accessToken, err := h.tokenIssuer.IssueAccessToken(ctx, authCode.UserID, authCode.ClientID, authCode.Scope)
	if err != nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to issue access_token", "token_access_issue_failed")
	}
	expiresIn := int(h.cfg.JWTAccessTTL.Seconds())

	resp := fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}

	// OIDC id_token is only included when `openid` is requested.
	if strings.Contains(authCode.Scope, "openid") {
		if authCode.Nonce == "" {
			return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing nonce in authorization code", "token_openid_nonce_missing_on_code")
		}
		if h.tokenIssuer == nil {
			return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "id_token issuer not configured", "token_id_token_issuer_nil")
		}
		idToken, err := h.tokenIssuer.IssueIDToken(ctx, authCode.UserID, authCode.ClientID, authCode.Nonce)
		if err != nil {
			return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to issue id_token", "token_id_token_issue_failed")
		}
		resp["id_token"] = idToken
	}

	slog.Info("token_authorization_code_success",
		"request_id", requestid.FromContext(c),
		"client_id", authCode.ClientID,
		"user_id", authCode.UserID,
		"scope", authCode.Scope,
		"id_token_present", resp["id_token"] != nil,
	)
	return c.JSON(resp)
}

func (h *Handlers) tokenPassword(c fiber.Ctx) error {
	ctx := c

	username := c.FormValue("username")
	password := c.FormValue("password")
	clientID := c.FormValue("client_id")
	scope := c.FormValue("scope")
	nonce := c.FormValue("nonce")

	if username == "" || password == "" || clientID == "" {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing username, password, or client_id", "token_password_missing_required_params")
	}

	client, err := h.store.GetClientByClientID(ctx, clientID)
	if err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_client", "invalid client_id", "token_password_client_not_found")
	}
	if !contains(client.AllowedGrantTypes, "password") {
		return h.oauthError(c, fiber.StatusBadRequest, "unauthorized_client", "grant not allowed", "token_password_grant_not_allowed")
	}

	requestScopes := splitScopes(scope)
	if !scopesAllAllowed(requestScopes, client.AllowedScopes) {
		return h.oauthError(c, fiber.StatusBadRequest, "invalid_scope", "scope not allowed", "token_password_scope_not_allowed")
	}

	user, err := h.store.GetUserByUsername(ctx, username)
	if err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "access_denied", "invalid credentials", "token_password_user_not_found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "access_denied", "invalid credentials", "token_password_mismatch")
	}

	if err := h.requireClientSecret(c, client); err != nil {
		return err
	}

	if h.tokenIssuer == nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "token issuer not configured", "token_password_access_issuer_nil")
	}
	accessToken, err := h.tokenIssuer.IssueAccessToken(ctx, user.ID, clientID, strings.Join(requestScopes, " "))
	if err != nil {
		return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to issue access_token", "token_password_access_issue_failed")
	}
	expiresIn := int(h.cfg.JWTAccessTTL.Seconds())

	resp := fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}

	if contains(requestScopes, "openid") {
		if nonce == "" {
			return h.oauthError(c, fiber.StatusBadRequest, "invalid_request", "missing nonce for openid scope", "token_password_missing_nonce_for_openid")
		}
		if h.tokenIssuer == nil {
			return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "id_token issuer not configured", "token_password_id_token_issuer_nil")
		}
		idToken, err := h.tokenIssuer.IssueIDToken(ctx, user.ID, clientID, nonce)
		if err != nil {
			return h.oauthError(c, fiber.StatusInternalServerError, "server_error", "failed to issue id_token", "token_password_id_token_issue_failed")
		}
		resp["id_token"] = idToken
	}

	slog.Info("token_password_success",
		"request_id", requestid.FromContext(c),
		"client_id", clientID,
		"user_id", user.ID,
		"scope", strings.Join(requestScopes, " "),
		"id_token_present", resp["id_token"] != nil,
	)
	return c.JSON(resp)
}

// requireClientSecret enforces client_secret for confidential clients (client_secret_hash set).
func (h *Handlers) requireClientSecret(c fiber.Ctx, client postgres.Client) error {
	if client.ClientSecretHash == nil || strings.TrimSpace(*client.ClientSecretHash) == "" {
		return nil
	}
	provided := c.FormValue("client_secret")
	if provided == "" {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_client", "missing client_secret", "token_client_secret_missing")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*client.ClientSecretHash), []byte(provided)); err != nil {
		return h.oauthError(c, fiber.StatusUnauthorized, "invalid_client", "invalid client_secret", "token_client_secret_mismatch")
	}
	return nil
}

func (h *Handlers) oauthError(c fiber.Ctx, status int, oauthErr, description, cause string) error {
	reqID := requestid.FromContext(c)
	if reqID == "" {
		reqID = c.Get(fiber.HeaderXRequestID)
	}

	level := slog.LevelWarn
	if status >= 500 {
		level = slog.LevelError
	}
	slog.Log(c, level, "oauth_error_response",
		"request_id", reqID,
		"method", c.Method(),
		"path", c.Path(),
		"status", status,
		"oauth_error", oauthErr,
		"cause", cause,
	)

	return c.Status(status).JSON(fiber.Map{
		"error":             oauthErr,
		"error_description": description,
		"cause":             cause,
		"request_id":        reqID,
	})
}

func pkceS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func splitScopes(scope string) []string {
	parts := strings.Fields(scope)
	return parts
}

func contains[T comparable](xs []T, target T) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}

func parseRedirectURIs(jsonText string) ([]string, error) {
	if jsonText == "" {
		return nil, errors.New("empty redirect_uris")
	}
	var uris []string
	if err := json.Unmarshal([]byte(jsonText), &uris); err != nil {
		return nil, err
	}
	return uris, nil
}

func scopesAllAllowed(requested []string, allowed []string) bool {
	allowedSet := map[string]struct{}{}
	for _, s := range allowed {
		allowedSet[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allowedSet[s]; !ok {
			return false
		}
	}
	return true
}

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// Fallback: not cryptographically strong, but avoids crashing.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func redirectWithCode(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return fmt.Sprintf("%s?code=%s&state=%s", redirectURI, url.QueryEscape(code), url.QueryEscape(state))
	}
	q := u.Query()
	q.Set("code", code)
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}
