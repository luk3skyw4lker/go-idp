package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	crypto2 "github.com/luk3skyw4lker/go-idp/internal/crypto"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"

	gojwt "github.com/luk3skyw4lker/go-jwt/v2/jwt"
	gojws "github.com/luk3skyw4lker/go-jwt/v2/signing/rsa"
)

type Handlers struct {
	cfg    config.Config
	store  *postgres.Store
	keyMgr *crypto2.KeyManager
}

func NewHandlers(cfg config.Config, store *postgres.Store, keyMgr *crypto2.KeyManager) *Handlers {
	return &Handlers{
		cfg:    cfg,
		store:  store,
		keyMgr: keyMgr,
	}
}

func (h *Handlers) Discovery(c fiber.Ctx) error {
	base := h.cfg.PublicIssuerURL
	discovery := fiber.Map{
		"issuer":                 base,
		"authorization_endpoint": base + "/authorize",
		"token_endpoint":         base + "/token",
		"userinfo_endpoint":      base + "/userinfo",
		"jwks_uri":               base + "/jwks",
		"response_types_supported": []string{
			"code",
		},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	}
	slog.Info("oidc_discovery_served",
		"request_id", requestIDFromCtx(c),
		"issuer", base,
	)
	return c.JSON(discovery)
}

func (h *Handlers) JWKS(c fiber.Ctx) error {
	ctx := c
	_, pub, meta, err := h.keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		return h.oidcError(c, fiber.StatusInternalServerError, "server_error", "failed to load active signing key", "jwks_active_key_load_failed")
	}

	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())

	jwks := fiber.Map{
		"keys": []fiber.Map{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": meta.Kid,
				"n":   n,
				"e":   e,
			},
		},
	}
	slog.Info("oidc_jwks_served",
		"request_id", requestIDFromCtx(c),
		"kid", meta.Kid,
		"key_count", 1,
	)

	return c.JSON(jwks)
}

// IssueIDToken creates a signed OIDC id_token with RS256.
// audience should typically be the OAuth client_id.
func (h *Handlers) IssueIDToken(ctx context.Context, userID string, audience string, nonce string) (string, error) {
	if userID == "" || audience == "" {
		return "", errors.New("missing userID or audience")
	}

	_, _, meta, err := h.keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		return "", err
	}

	// Load PEM bytes for go-jwt signing.
	privPemBytes, err := os.ReadFile(meta.PrivatePemPath)
	if err != nil {
		return "", err
	}
	pubPemBytes, err := os.ReadFile(meta.PublicPemPath)
	if err != nil {
		return "", err
	}

	alg, err := gojws.New(crypto.SHA256, string(privPemBytes), string(pubPemBytes))
	if err != nil {
		return "", fmt.Errorf("create RSA signer: %w", err)
	}

	gen := gojwt.NewGenerator(alg, gojwt.Options{ShouldPad: false})

	now := time.Now()
	payload := map[string]any{
		"iss": h.cfg.PublicIssuerURL,
		"sub": userID,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(h.cfg.JWTIDTTL).Unix(),
	}
	if nonce != "" {
		payload["nonce"] = nonce
	}

	token, err := signJWT(gen, payload)
	if err != nil {
		return "", fmt.Errorf("generate id_token: %w", err)
	}
	slog.Info("oidc_id_token_issued",
		"subject", userID,
		"audience", audience,
		"nonce_present", nonce != "",
	)

	return token, nil
}

// IssueAccessToken creates a signed JWT access token (at+jwt style claims).
func (h *Handlers) IssueAccessToken(ctx context.Context, userID string, audience string, scope string) (string, error) {
	if userID == "" || audience == "" {
		return "", errors.New("missing userID or audience")
	}

	_, _, meta, err := h.keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		return "", err
	}

	privPemBytes, err := os.ReadFile(meta.PrivatePemPath)
	if err != nil {
		return "", err
	}
	pubPemBytes, err := os.ReadFile(meta.PublicPemPath)
	if err != nil {
		return "", err
	}

	alg, err := gojws.New(crypto.SHA256, string(privPemBytes), string(pubPemBytes))
	if err != nil {
		return "", fmt.Errorf("create RSA signer: %w", err)
	}
	gen := gojwt.NewGenerator(alg, gojwt.Options{ShouldPad: false})

	now := time.Now()
	claims := map[string]any{
		"iss":       h.cfg.PublicIssuerURL,
		"sub":       userID,
		"aud":       audience,
		"iat":       now.Unix(),
		"exp":       now.Add(h.cfg.JWTAccessTTL).Unix(),
		"scope":     scope,
		"token_use": "access",
		"jti":       randomID(16),
	}

	token, err := signJWT(gen, claims)
	if err != nil {
		return "", fmt.Errorf("generate access_token: %w", err)
	}
	slog.Info("oidc_access_token_issued",
		"subject", userID,
		"audience", audience,
		"scope", scope,
	)
	return token, nil
}

func (h *Handlers) UserInfo(c fiber.Ctx) error {
	userID, source, err := h.userIDFromSessionOrJWT(c)
	if err != nil {
		return h.oidcError(c, fiber.StatusUnauthorized, "invalid_token", "not authenticated", "userinfo_session_and_jwt_missing_or_invalid")
	}

	user, err := h.store.GetUserByID(c, userID)
	if err != nil {
		return h.oidcError(c, fiber.StatusUnauthorized, "invalid_token", "not authenticated", "userinfo_user_not_found")
	}

	claims := fiber.Map{
		"sub":      user.ID,
		"username": user.Username,
		"name":     user.DisplayName,
		"email":    user.Email,
		// Additional claims can be added once `/userinfo` scope-to-claims mapping is implemented.
	}
	slog.Info("oidc_userinfo_served",
		"request_id", requestIDFromCtx(c),
		"sub", userID,
		"auth_source", source,
	)
	return c.JSON(claims)
}

func (h *Handlers) userIDFromSessionOrJWT(c fiber.Ctx) (string, string, error) {
	if userID, ok := session.UserIDFromContext(c); ok && userID != "" {
		return userID, "session_cookie", nil
	}

	authz := strings.TrimSpace(c.Get(fiber.HeaderAuthorization))
	if !strings.HasPrefix(strings.ToLower(authz), "bearer ") {
		return "", "", errors.New("no bearer token")
	}
	token := strings.TrimSpace(authz[len("Bearer "):])
	if token == "" {
		return "", "", errors.New("empty bearer token")
	}

	if !looksLikeJWT(token) {
		slog.Info("userinfo_bearer_not_jwt",
			"request_id", requestIDFromCtx(c),
			"token", token,
			"token_len", len(token),
		)
		return "", "", errors.New("bearer token is not a jwt")
	}

	if err := h.verifyJWT(c, token); err != nil {
		return "", "", err
	}
	sub, err := extractJWTSub(token)
	if err != nil {
		return "", "", err
	}
	if sub == "" {
		return "", "", errors.New("missing sub in jwt")
	}
	return sub, "jwt_bearer", nil
}

func (h *Handlers) verifyJWT(ctx context.Context, token string) error {
	_, _, meta, err := h.keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		return fmt.Errorf("load active key: %w", err)
	}
	privPemBytes, err := os.ReadFile(meta.PrivatePemPath)
	if err != nil {
		return fmt.Errorf("read private pem: %w", err)
	}
	pubPemBytes, err := os.ReadFile(meta.PublicPemPath)
	if err != nil {
		return fmt.Errorf("read public pem: %w", err)
	}

	alg, err := gojws.New(crypto.SHA256, string(privPemBytes), string(pubPemBytes))
	if err != nil {
		return fmt.Errorf("create jwt verifier: %w", err)
	}
	gen := gojwt.NewGenerator(alg, gojwt.Options{ShouldPad: false})
	ok, err := gen.Verify(token)
	if err != nil {
		return fmt.Errorf("verify jwt: %w", err)
	}
	if !ok {
		return errors.New("jwt verify failed")
	}
	return nil
}

func extractJWTSub(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid jwt format")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode jwt payload: %w", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return "", fmt.Errorf("parse jwt payload: %w", err)
	}
	slog.Info("jwt_payload_parsed",
		"payload", payload,
	)
	sub, _ := payload["sub"].(string)
	slog.Info("jwt_sub_extracted",
		"sub", sub,
	)
	return sub, nil
}

func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) == 3 && parts[0] != "" && parts[1] != "" && parts[2] != ""
}

func (h *Handlers) oidcError(c fiber.Ctx, status int, oauthErr, description, cause string) error {
	level := slog.LevelWarn
	if status >= 500 {
		level = slog.LevelError
	}
	reqID := requestIDFromCtx(c)
	slog.Log(c, level, "oidc_error_response",
		"request_id", reqID,
		"method", c.Method(),
		"path", c.Path(),
		"status", status,
		"error", oauthErr,
		"cause", cause,
	)
	return c.Status(status).JSON(fiber.Map{
		"error":             oauthErr,
		"error_description": description,
		"cause":             cause,
		"request_id":        reqID,
	})
}

func requestIDFromCtx(c fiber.Ctx) string {
	reqID := requestid.FromContext(c)
	if reqID == "" {
		reqID = c.Get(fiber.HeaderXRequestID)
	}
	return reqID
}

func signJWT(gen *gojwt.JWTGenerator, claims map[string]any) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	// Use library default header (alg/typ set by signer package).
	return gen.Generate(claimsBytes)
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
