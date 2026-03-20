package http

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/luk3skyw4lker/go-idp/internal/auth"
	"github.com/luk3skyw4lker/go-idp/internal/config"
	crypto2 "github.com/luk3skyw4lker/go-idp/internal/crypto"
	"github.com/luk3skyw4lker/go-idp/internal/oauth2"
	"github.com/luk3skyw4lker/go-idp/internal/oidc"
	"github.com/luk3skyw4lker/go-idp/internal/saml"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
)

// NewApp creates the Fiber server and wires placeholder routes.
// Protocol logic is implemented in later steps.
func NewApp(cfg config.Config, store *postgres.Store) *fiber.App {
	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
	})

	// Middleware required by the plan.
	app.Use(requestid.New())
	app.Use(recover.New())
	app.Use(session.Middleware(session.MiddlewareOptions{
		Store:        store,
		SessionTTL:   cfg.SessionTTL,
		CookieSecure: cfg.CookieSecure,
	}))

	// Health
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).SendString("ok")
	})

	// Auth UI
	login := auth.NewLoginHandlers(store, cfg.SessionTTL, cfg.CookieSecure)
	app.Get("/login", login.GetLogin)
	app.Post("/login", login.PostLogin)

	// OIDC / OAuth2
	keyMgr := crypto2.NewKeyManager(store, cfg.DevKeysDir)
	oidcH := oidc.NewHandlers(cfg, store, keyMgr)

	oauth := oauth2.NewHandlers(store, cfg, oidcH)
	app.Get("/.well-known/openid-configuration", oidcH.Discovery)
	app.Get("/jwks", oidcH.JWKS)
	app.Get("/authorize", oauth.Authorize)
	app.Post("/token", oauth.Token)
	app.Get("/userinfo", oidcH.UserInfo)

	// SAML
	samlH := saml.NewHandlers(cfg, store)
	app.Post("/saml/sso", samlH.SSO)
	app.Get("/saml/sso", samlH.SSO)
	app.Get("/saml/metadata", samlH.Metadata)

	return app
}
