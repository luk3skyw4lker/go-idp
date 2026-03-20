package oidc

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
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

func (h *Handlers) Discovery(c *fiber.Ctx) error {
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
	return c.JSON(discovery)
}

func (h *Handlers) JWKS(c *fiber.Ctx) error {
	ctx := c.Context()
	_, pub, meta, err := h.keyMgr.EnsureActiveKey(ctx)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).SendString("failed to load active signing key")
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

	claimsBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Use the library's default JWT header for compatibility with its RS256 signer.
	token, err := gen.Generate(claimsBytes)
	if err != nil {
		return "", fmt.Errorf("generate id_token: %w", err)
	}

	return token, nil
}

func (h *Handlers) UserInfo(c *fiber.Ctx) error {
	userID, ok := session.UserIDFromContext(c)
	if !ok || userID == "" {
		return c.Status(fiber.StatusUnauthorized).SendString("not authenticated")
	}

	claims := fiber.Map{
		"sub": userID,
		// Additional claims can be added once `/userinfo` scope-to-claims mapping is implemented.
	}
	return c.JSON(claims)
}
