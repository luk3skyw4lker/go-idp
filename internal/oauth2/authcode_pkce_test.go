package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

type mockStore struct {
	client          postgres.Client
	user            postgres.User
	authCode        postgres.AuthorizationCode
	authCodeEnabled bool
}

func (m *mockStore) GetClientByClientID(ctx context.Context, clientID string) (postgres.Client, error) {
	return m.client, nil
}

func (m *mockStore) PutPendingAuthRequest(ctx context.Context, req postgres.PendingAuthRequest) error {
	return nil
}

func (m *mockStore) CreateAuthorizationCode(ctx context.Context, code postgres.AuthorizationCode) error {
	return nil
}

func (m *mockStore) ConsumeAuthorizationCode(ctx context.Context, code string) (postgres.AuthorizationCode, error) {
	if !m.authCodeEnabled {
		return postgres.AuthorizationCode{}, errors.New("auth code not configured in mock")
	}
	return m.authCode, nil
}

func (m *mockStore) GetUserByUsername(ctx context.Context, username string) (postgres.User, error) {
	return m.user, nil
}

type mockIDTokenIssuer struct {
	calls       int
	token       string
	err         error
	accessToken string
	accessErr   error
	accessCalls int
	accessLast  struct {
		userID   string
		audience string
		scope    string
	}
	last struct {
		userID   string
		audience string
		nonce    string
	}
}

func (m *mockIDTokenIssuer) IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error) {
	m.calls++
	m.last.userID = userID
	m.last.audience = audience
	m.last.nonce = nonce
	if m.err != nil {
		return "", m.err
	}
	return m.token, nil
}

func (m *mockIDTokenIssuer) IssueAccessToken(ctx context.Context, userID string, audience string, scope string) (string, error) {
	m.accessCalls++
	m.accessLast.userID = userID
	m.accessLast.audience = audience
	m.accessLast.scope = scope
	if m.accessErr != nil {
		return "", m.accessErr
	}
	if m.accessToken != "" {
		return m.accessToken, nil
	}
	return "access-token", nil
}

func newPasswordGrantHandler(t *testing.T, issuer *mockIDTokenIssuer) *Handlers {
	t.Helper()
	return newPasswordGrantHandlerWithClient(t, issuer, nil)
}

func newPasswordGrantHandlerWithClient(t *testing.T, issuer *mockIDTokenIssuer, client *postgres.Client) *Handlers {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}
	c := postgres.Client{
		ClientID:                "demo-client",
		AllowedGrantTypes:       []string{"password"},
		AllowedScopes:           []string{"openid"},
		RedirectURIsJSON:        `["http://localhost:8081/callback"]`,
		ClientSecretHash:        nil,
		TokenEndpointAuthMethod: "none",
	}
	if client != nil {
		c = *client
	}
	store := &mockStore{
		client: c,
		user: postgres.User{
			ID:           "u1",
			Username:     "alice",
			PasswordHash: string(hash),
		},
	}
	cfg := config.Config{
		JWTAccessTTL: 15 * time.Minute,
	}
	return NewHandlers(store, cfg, issuer)
}

func performTokenRequest(t *testing.T, h *Handlers, body string) *http.Response {
	t.Helper()
	app := fiber.New()
	app.Post("/token", h.Token)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("app test: %v", err)
	}
	return resp
}

func TestTokenPassword_NoScope_DoesNotRequireNonce(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "id-token"}
	h := newPasswordGrantHandler(t, issuer)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("username", "alice")
	form.Set("password", "password123")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["id_token"] != nil {
		t.Fatalf("expected no id_token when scope is omitted")
	}
	if issuer.calls != 0 {
		t.Fatalf("expected id token issuer not to be called")
	}
}

func TestTokenPassword_OpenIDWithoutNonce_ReturnsBadRequest(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "id-token"}
	h := newPasswordGrantHandler(t, issuer)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("username", "alice")
	form.Set("password", "password123")
	form.Set("scope", "openid")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if issuer.calls != 0 {
		t.Fatalf("expected id token issuer not to be called")
	}
}

func TestTokenPassword_OpenIDWithNonce_IssuesIDToken(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "signed-token"}
	h := newPasswordGrantHandler(t, issuer)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("username", "alice")
	form.Set("password", "password123")
	form.Set("scope", "openid")
	form.Set("nonce", "n-123")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["id_token"] != "signed-token" {
		t.Fatalf("unexpected id_token: %v", body["id_token"])
	}
	if issuer.calls != 1 {
		t.Fatalf("expected id token issuer to be called once, got %d", issuer.calls)
	}
	if issuer.last.userID != "u1" || issuer.last.audience != "demo-client" || issuer.last.nonce != "n-123" {
		t.Fatalf("unexpected issuer args: %#v", issuer.last)
	}
}

func confidentialClient(t *testing.T, secretPlain string) postgres.Client {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(secretPlain), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	s := string(h)
	return postgres.Client{
		ClientID:                "demo-client",
		AllowedGrantTypes:       []string{"password", "authorization_code"},
		AllowedScopes:           []string{"openid"},
		RedirectURIsJSON:        `["http://localhost:8081/callback"]`,
		ClientSecretHash:        &s,
		TokenEndpointAuthMethod: "client_secret_post",
	}
}

func TestTokenPassword_Confidential_MissingClientSecret(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "id-token"}
	c := confidentialClient(t, "s3cr3t")
	h := newPasswordGrantHandlerWithClient(t, issuer, &c)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("username", "alice")
	form.Set("password", "password123")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestTokenPassword_Confidential_InvalidClientSecret(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "id-token"}
	c := confidentialClient(t, "s3cr3t")
	h := newPasswordGrantHandlerWithClient(t, issuer, &c)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("client_secret", "wrong")
	form.Set("username", "alice")
	form.Set("password", "password123")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestTokenPassword_Confidential_WithClientSecret(t *testing.T) {
	issuer := &mockIDTokenIssuer{token: "id-token"}
	c := confidentialClient(t, "s3cr3t")
	h := newPasswordGrantHandlerWithClient(t, issuer, &c)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "demo-client")
	form.Set("client_secret", "s3cr3t")
	form.Set("username", "alice")
	form.Set("password", "password123")

	resp := performTokenRequest(t, h, form.Encode())
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestTokenAuthorizationCode_Confidential_RequiresClientSecret(t *testing.T) {
	verifier := strings.Repeat("a", 48)
	challenge := pkceS256(verifier)
	c := confidentialClient(t, "s3cr3t")

	store := &mockStore{
		client: c,
		user: postgres.User{
			ID:           "u1",
			Username:     "alice",
			PasswordHash: "x",
		},
		authCodeEnabled: true,
		authCode: postgres.AuthorizationCode{
			Code:                "authcode1",
			ClientID:            "demo-client",
			RedirectURI:         "http://localhost:8081/callback",
			CodeChallenge:       challenge,
			CodeChallengeMethod: "S256",
			Scope:               "",
			UserID:              "u1",
		},
	}
	cfg := config.Config{JWTAccessTTL: 15 * time.Minute}
	h := NewHandlers(store, cfg, &mockIDTokenIssuer{token: "id"})

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", "authcode1")
	form.Set("code_verifier", verifier)
	form.Set("client_id", "demo-client")
	form.Set("redirect_uri", "http://localhost:8081/callback")

	app := fiber.New()
	app.Post("/token", h.Token)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 without client_secret, got %d", resp.StatusCode)
	}

	form.Set("client_secret", "s3cr3t")
	req = httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = app.Test(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with client_secret, got %d", resp.StatusCode)
	}
}
