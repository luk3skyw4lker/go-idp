package integration_test

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luk3skyw4lker/go-idp/internal/config"
	idphttp "github.com/luk3skyw4lker/go-idp/internal/http"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"

	"github.com/gofiber/fiber/v3"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type testSetup struct {
	cfg         config.Config
	pool        *pgxpool.Pool
	store       *postgres.Store
	app         *fiber.App
	username    string
	password    string
	userID      string
	clientID    string
	redirectURI string
	spIssuer    string
	spAcsURL    string
}

func setup(t *testing.T) testSetup {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("integration config load failed (set envs or root config.yml): %v", err)
	}
	cfg.ListenAddr = ":0"
	cfg.PublicIssuerURL = strings.TrimRight(cfg.PublicIssuerURL, "/")
	if cfg.MigrationsDir == "" {
		cfg.MigrationsDir = "./migrations"
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 24 * time.Hour
	}
	if cfg.JWTAccessTTL == 0 {
		cfg.JWTAccessTTL = 15 * time.Minute
	}
	if cfg.JWTIDTTL == 0 {
		cfg.JWTIDTTL = 15 * time.Minute
	}
	if cfg.DevKeysDir == "" {
		cfg.DevKeysDir = "./test-dev-keys"
	}

	ctx := context.Background()
	pool, err := postgres.NewPoolFromURL(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatalf("db connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	if err := postgres.Migrate(ctx, pool, cfg.MigrationsDir); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store := postgres.NewStore(pool)
	app := idphttp.NewApp(cfg, store)

	// Seed deterministic user/client/SP to make this test self-contained.
	username := "it_user"
	password := "it_pass"
	userHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("bcrypt hash: %v", err)
	}

	var userID string
	if err := pool.QueryRow(
		ctx,
		`INSERT INTO users (username, password_hash, display_name, email)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (username)
		 DO UPDATE SET password_hash=EXCLUDED.password_hash, display_name=EXCLUDED.display_name, email=EXCLUDED.email
		 RETURNING id`,
		username, string(userHash), "it_user", "",
	).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	clientID := "it_client"
	redirectURI := "http://localhost/callback"
	redirectJSON := mustJSON(t, []string{redirectURI})
	client := postgres.Client{
		ClientID:                clientID,
		ClientSecretHash:        nil,
		RedirectURIsJSON:        redirectJSON,
		TokenEndpointAuthMethod: "none",
		AllowedGrantTypes:       []string{"authorization_code", "password"},
		AllowedScopes:           []string{"openid"},
	}
	if err := store.UpsertClient(ctx, client); err != nil {
		t.Fatalf("seed client: %v", err)
	}

	spIssuer := "it_sp_issuer"
	spAcsURL := "http://sp.example/acs"
	nameIDFormat := "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
	sp := postgres.SamlSP{
		Issuer:       spIssuer,
		AcsURL:       spAcsURL,
		AudienceURI:  nil,
		NameIDFormat: &nameIDFormat,
	}
	if err := store.UpsertSamlSP(ctx, sp); err != nil {
		t.Fatalf("seed saml sp: %v", err)
	}

	return testSetup{
		cfg:         cfg,
		pool:        pool,
		store:       store,
		app:         app,
		username:    username,
		password:    password,
		userID:      userID,
		clientID:    clientID,
		redirectURI: redirectURI,
		spIssuer:    spIssuer,
		spAcsURL:    spAcsURL,
	}
}

func doRequest(t *testing.T, app *fiber.App, req *http.Request) *http.Response {
	t.Helper()
	resp, err := app.Test(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	return resp
}

func firstSetCookie(resp *http.Response, cookieName string) (string, bool) {
	for _, sc := range resp.Header.Values("Set-Cookie") {
		parts := strings.Split(sc, ";")
		if len(parts) == 0 {
			continue
		}
		kvs := strings.SplitN(parts[0], "=", 2)
		if len(kvs) == 2 && kvs[0] == cookieName {
			return kvs[1], true
		}
	}
	return "", false
}

func TestOIDC_AuthorizationCode_PKCE(t *testing.T) {
	s := setup(t)

	ctx := context.Background()
	_ = ctx

	// PKCE + OIDC parameters.
	nonce := "it_nonce"
	codeVerifier := randToken(32)
	codeChallenge := pkceS256(codeVerifier)
	state := "it_state"

	authorizeURL := s.cfg.PublicIssuerURL + "/authorize"
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", s.redirectURI)
	q.Set("scope", "openid")
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	req := httptest.NewRequest(http.MethodGet, "/authorize?"+q.Encode(), nil)
	resp := doRequest(t, s.app, req)
	if !isRedirect(resp.StatusCode) {
		t.Fatalf("expected redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("missing Location")
	}

	// Extract pending_id from redirect to /login.
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location: %v", err)
	}
	pendingID := u.Query().Get("pending_id")
	if pendingID == "" {
		t.Fatalf("missing pending_id")
	}

	// POST /login to create authorization code + session cookie.
	form := url.Values{}
	form.Set("username", s.username)
	form.Set("password", s.password)
	form.Set("pending_id", pendingID)

	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp := doRequest(t, s.app, loginReq)
	if !isRedirect(loginResp.StatusCode) {
		t.Fatalf("expected redirect from login, got %d", loginResp.StatusCode)
	}
	sessionCookie, ok := firstSetCookie(loginResp, "idp_session")
	if !ok {
		t.Fatalf("missing idp_session cookie")
	}

	loginLoc := loginResp.Header.Get("Location")
	u, err = url.Parse(loginLoc)
	if err != nil {
		t.Fatalf("parse login redirect location: %v", err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in login redirect")
	}
	if u.Query().Get("state") != state {
		t.Fatalf("state mismatch")
	}

	// POST /token to exchange code for tokens.
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", code)
	tokenForm.Set("code_verifier", codeVerifier)
	tokenForm.Set("client_id", s.clientID)
	tokenForm.Set("redirect_uri", s.redirectURI)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp := doRequest(t, s.app, tokenReq)
	if tokenResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status: %d body=%s", tokenResp.StatusCode, string(b))
	}
	var tokenBody map[string]any
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenBody); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if tokenBody["id_token"] == nil {
		t.Fatalf("expected id_token for openid scope")
	}
	if tokenBody["id_token"] == "id_token_not_implemented" {
		t.Fatalf("id_token not signed")
	}

	// GET /userinfo using the session cookie.
	userReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	userReq.Header.Set("Cookie", "idp_session="+sessionCookie)
	userResp := doRequest(t, s.app, userReq)
	if userResp.StatusCode != http.StatusOK {
		t.Fatalf("userinfo status: %d", userResp.StatusCode)
	}
	var userBody map[string]any
	if err := json.NewDecoder(userResp.Body).Decode(&userBody); err != nil {
		t.Fatalf("decode userinfo: %v", err)
	}
	if userBody["sub"] != s.userID {
		t.Fatalf("userinfo sub mismatch: got=%v want=%v", userBody["sub"], s.userID)
	}

	_ = authorizeURL
}

func TestOAuth2_PasswordGrant(t *testing.T) {
	s := setup(t)

	tests := []struct {
		name           string
		form           url.Values
		wantStatusCode int
		wantIDToken    bool
	}{
		{
			name: "access token only when scope omitted",
			form: url.Values{
				"grant_type": {"password"},
				"username":   {s.username},
				"password":   {s.password},
				"client_id":  {s.clientID},
			},
			wantStatusCode: http.StatusOK,
			wantIDToken:    false,
		},
		{
			name: "openid without nonce is rejected",
			form: url.Values{
				"grant_type": {"password"},
				"username":   {s.username},
				"password":   {s.password},
				"client_id":  {s.clientID},
				"scope":      {"openid"},
			},
			wantStatusCode: http.StatusBadRequest,
			wantIDToken:    false,
		},
		{
			name: "openid with nonce returns id_token",
			form: url.Values{
				"grant_type": {"password"},
				"username":   {s.username},
				"password":   {s.password},
				"client_id":  {s.clientID},
				"scope":      {"openid"},
				"nonce":      {"it_nonce_password"},
			},
			wantStatusCode: http.StatusOK,
			wantIDToken:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tt.form.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp := doRequest(t, s.app, req)

			if resp.StatusCode != tt.wantStatusCode {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("status: got=%d want=%d body=%s", resp.StatusCode, tt.wantStatusCode, string(b))
			}

			if resp.StatusCode != http.StatusOK {
				return
			}

			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode token response: %v", err)
			}

			_, hasAccess := body["access_token"]
			if !hasAccess {
				t.Fatalf("missing access_token")
			}
			_, hasID := body["id_token"]
			if hasID != tt.wantIDToken {
				t.Fatalf("id_token presence mismatch: got=%v want=%v", hasID, tt.wantIDToken)
			}
		})
	}
}

func TestCoreEndpoints(t *testing.T) {
	s := setup(t)

	type endpointCase struct {
		path string
	}
	cases := []endpointCase{
		{path: "/healthz"},
		{path: "/.well-known/openid-configuration"},
		{path: "/jwks"},
		{path: "/saml/metadata"},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			resp := doRequest(t, s.app, req)
			if resp.StatusCode != http.StatusOK {
				b, _ := io.ReadAll(resp.Body)
				t.Fatalf("endpoint %s status: %d body=%s", tc.path, resp.StatusCode, string(b))
			}
		})
	}
}

func TestSAML_SPInitiated_POST(t *testing.T) {
	s := setup(t)

	// Minimal SAML AuthnRequest XML.
	now := time.Now().UTC().Format(time.RFC3339)
	authnReqXML := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="_it_authn_1" Version="2.0" IssueInstant="%s"
  Destination="%s" AssertionConsumerServiceURL="%s">
  <saml:Issuer>%s</saml:Issuer>
</samlp:AuthnRequest>`, now, s.cfg.PublicIssuerURL+"/saml/sso", s.spAcsURL, s.spIssuer)

	authnReqB64 := base64.StdEncoding.EncodeToString([]byte(authnReqXML))
	relayState := "it_relay_" + randToken(6)

	// POST /saml/sso without session => pending + redirect to /login.
	form := url.Values{}
	form.Set("SAMLRequest", authnReqB64)
	form.Set("RelayState", relayState)

	postReq := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp := doRequest(t, s.app, postReq)
	if !isRedirect(postResp.StatusCode) {
		t.Fatalf("expected redirect, got %d", postResp.StatusCode)
	}
	loc := postResp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("missing Location")
	}

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	pendingID := u.Query().Get("pending_saml_id")
	if pendingID == "" {
		t.Fatalf("missing pending_saml_id")
	}

	// Login and resume.
	loginForm := url.Values{}
	loginForm.Set("username", s.username)
	loginForm.Set("password", s.password)
	loginForm.Set("pending_saml_id", pendingID)

	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(loginForm.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp := doRequest(t, s.app, loginReq)
	if !isRedirect(loginResp.StatusCode) {
		t.Fatalf("expected redirect from login, got %d", loginResp.StatusCode)
	}

	sessionCookie, ok := firstSetCookie(loginResp, "idp_session")
	if !ok {
		t.Fatalf("missing idp_session cookie")
	}

	// GET /saml/sso?pending_saml_id=... to obtain SAMLResponse HTML.
	resumeReq := httptest.NewRequest(http.MethodGet, "/saml/sso?pending_saml_id="+url.QueryEscape(pendingID), nil)
	resumeReq.Header.Set("Cookie", "idp_session="+sessionCookie)
	resumeResp := doRequest(t, s.app, resumeReq)
	if resumeResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resumeResp.Body)
		t.Fatalf("resume status: %d body=%s", resumeResp.StatusCode, string(b))
	}
	bodyBytes, err := io.ReadAll(resumeResp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	html := string(bodyBytes)

	if !strings.Contains(html, "name=\"SAMLResponse\"") {
		t.Fatalf("missing SAMLResponse in HTML")
	}

	// Extract SAMLResponse value.
	idx := strings.Index(html, `name="SAMLResponse"`)
	if idx < 0 {
		t.Fatalf("SAMLResponse input not found")
	}
	// very small parser: find value="...".
	valIdx := strings.Index(html[idx:], `value="`)
	if valIdx < 0 {
		t.Fatalf("SAMLResponse value not found")
	}
	valIdx += idx + len(`value="`)
	valEnd := strings.Index(html[valIdx:], `"`)
	if valEnd < 0 {
		t.Fatalf("unterminated SAMLResponse value")
	}
	valEnd += valIdx
	samlRespB64 := html[valIdx:valEnd]
	if strings.TrimSpace(samlRespB64) == "" {
		t.Fatalf("empty SAMLResponse")
	}

	samlRespXMLBytes, err := base64.StdEncoding.DecodeString(samlRespB64)
	if err != nil {
		t.Fatalf("decode SAMLResponse: %v", err)
	}
	if !strings.Contains(string(samlRespXMLBytes), "samlp:Response") {
		t.Fatalf("unexpected SAMLResponse payload")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	return string(b)
}

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return strings.TrimRight(base64.RawURLEncoding.EncodeToString(b), "=")
}

func isRedirect(status int) bool {
	return status == http.StatusFound || status == http.StatusSeeOther
}
