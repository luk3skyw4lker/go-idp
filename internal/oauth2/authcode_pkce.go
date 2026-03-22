package oauth2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

type Handlers struct {
	store oauthStore
	cfg   config.Config

	idTokenIssuer interface {
		IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error)
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

func NewHandlers(store oauthStore, cfg config.Config, idTokenIssuer interface {
	IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error)
}) *Handlers {
	return &Handlers{
		store:            store,
		cfg:              cfg,
		idTokenIssuer:    idTokenIssuer,
		PendingAuthTTL:   10 * time.Minute,
		AuthorizationTTL: 10 * time.Minute,
	}
}

func (h *Handlers) Authorize(c *fiber.Ctx) error {
	ctx := c.Context()

	responseType := c.Query("response_type")
	if responseType != "code" {
		return c.Status(fiber.StatusBadRequest).SendString("unsupported response_type")
	}

	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	state := c.Query("state")
	scope := c.Query("scope")
	codeChallenge := c.Query("code_challenge")
	codeChallengeMethod := c.Query("code_challenge_method")
	nonce := c.Query("nonce")

	if clientID == "" || redirectURI == "" || state == "" || scope == "" || codeChallenge == "" || codeChallengeMethod == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing required parameters")
	}
	if codeChallengeMethod != "S256" {
		return c.Status(fiber.StatusBadRequest).SendString("unsupported code_challenge_method")
	}

	// Validate client.
	client, err := h.store.GetClientByClientID(ctx, clientID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid client_id")
	}

	if !contains(client.AllowedGrantTypes, "authorization_code") {
		return c.Status(fiber.StatusBadRequest).SendString("grant not allowed")
	}

	requestScopes := splitScopes(scope)
	if len(requestScopes) == 0 {
		return c.Status(fiber.StatusBadRequest).SendString("invalid scope")
	}

	// For OIDC, `nonce` is required when `openid` is requested.
	if contains(requestScopes, "openid") && nonce == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing nonce for openid scope")
	}

	if !scopesAllAllowed(requestScopes, client.AllowedScopes) {
		return c.Status(fiber.StatusBadRequest).SendString("scope not allowed")
	}

	redirectURIs, err := parseRedirectURIs(client.RedirectURIsJSON)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("client redirect_uris invalid")
	}
	if !contains(redirectURIs, redirectURI) {
		return c.Status(fiber.StatusBadRequest).SendString("redirect_uri not allowed")
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
			return c.Status(fiber.StatusInternalServerError).SendString("failed to persist pending auth request")
		}

		return c.Redirect(fmt.Sprintf("/login?pending_id=%s", url.QueryEscape(pendingID)))
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
		return c.Status(fiber.StatusInternalServerError).SendString("failed to create authorization code")
	}

	return c.Redirect(redirectWithCode(redirectURI, code, state))
}

func (h *Handlers) Token(c *fiber.Ctx) error {
	grantType := c.FormValue("grant_type")
	switch grantType {
	case "authorization_code":
		return h.tokenAuthorizationCode(c)
	case "password":
		return h.tokenPassword(c)
	default:
		return c.Status(fiber.StatusBadRequest).SendString("unsupported grant_type")
	}
}

func (h *Handlers) tokenAuthorizationCode(c *fiber.Ctx) error {
	ctx := c.Context()

	code := c.FormValue("code")
	codeVerifier := c.FormValue("code_verifier")
	clientID := c.FormValue("client_id")
	redirectURI := c.FormValue("redirect_uri")
	if code == "" || codeVerifier == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing code or code_verifier")
	}

	authCode, err := h.store.ConsumeAuthorizationCode(ctx, code)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid/expired authorization code")
	}

	// Client + redirect_uri binding.
	if clientID != "" && authCode.ClientID != clientID {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid client_id for code")
	}
	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid redirect_uri for code")
	}

	if authCode.CodeChallengeMethod != "S256" {
		return c.Status(fiber.StatusBadRequest).SendString("unsupported PKCE method")
	}

	expected := pkceS256(codeVerifier)
	if expected != authCode.CodeChallenge {
		return c.Status(fiber.StatusBadRequest).SendString("invalid code_verifier")
	}

	client, err := h.store.GetClientByClientID(ctx, authCode.ClientID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid client_id")
	}
	if err := h.requireClientSecret(c, client); err != nil {
		return err
	}

	accessToken := randomToken(40)
	expiresIn := int(h.cfg.JWTAccessTTL.Seconds())

	resp := fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}

	// OIDC id_token is only included when `openid` is requested.
	if strings.Contains(authCode.Scope, "openid") {
		if authCode.Nonce == "" {
			return c.Status(fiber.StatusBadRequest).SendString("missing nonce in authorization code")
		}
		if h.idTokenIssuer == nil {
			return c.Status(fiber.StatusInternalServerError).SendString("id_token issuer not configured")
		}
		idToken, err := h.idTokenIssuer.IssueIDToken(ctx, authCode.UserID, authCode.ClientID, authCode.Nonce)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("failed to issue id_token")
		}
		resp["id_token"] = idToken
	}

	return c.JSON(resp)
}

func (h *Handlers) tokenPassword(c *fiber.Ctx) error {
	ctx := c.Context()

	username := c.FormValue("username")
	password := c.FormValue("password")
	clientID := c.FormValue("client_id")
	scope := c.FormValue("scope")
	nonce := c.FormValue("nonce")

	if username == "" || password == "" || clientID == "" {
		return c.Status(fiber.StatusBadRequest).SendString("missing username, password, or client_id")
	}

	client, err := h.store.GetClientByClientID(ctx, clientID)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid client_id")
	}
	if !contains(client.AllowedGrantTypes, "password") {
		return c.Status(fiber.StatusBadRequest).SendString("grant not allowed")
	}

	requestScopes := splitScopes(scope)
	if !scopesAllAllowed(requestScopes, client.AllowedScopes) {
		return c.Status(fiber.StatusBadRequest).SendString("scope not allowed")
	}

	user, err := h.store.GetUserByUsername(ctx, username)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid credentials")
	}

	if err := h.requireClientSecret(c, client); err != nil {
		return err
	}

	accessToken := randomToken(40)
	expiresIn := int(h.cfg.JWTAccessTTL.Seconds())

	resp := fiber.Map{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}

	if contains(requestScopes, "openid") {
		if nonce == "" {
			return c.Status(fiber.StatusBadRequest).SendString("missing nonce for openid scope")
		}
		if h.idTokenIssuer == nil {
			return c.Status(fiber.StatusInternalServerError).SendString("id_token issuer not configured")
		}
		idToken, err := h.idTokenIssuer.IssueIDToken(ctx, user.ID, clientID, nonce)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString("failed to issue id_token")
		}
		resp["id_token"] = idToken
	}

	return c.JSON(resp)
}

// requireClientSecret enforces client_secret for confidential clients (client_secret_hash set).
func (h *Handlers) requireClientSecret(c *fiber.Ctx, client postgres.Client) error {
	if client.ClientSecretHash == nil || strings.TrimSpace(*client.ClientSecretHash) == "" {
		return nil
	}
	provided := c.FormValue("client_secret")
	if provided == "" {
		return c.Status(fiber.StatusUnauthorized).SendString("missing client_secret")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(*client.ClientSecretHash), []byte(provided)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid client_secret")
	}
	return nil
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
