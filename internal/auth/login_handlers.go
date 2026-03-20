package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/luk3skyw4lker/go-idp/internal/session"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
	"golang.org/x/crypto/bcrypt"
)

type LoginHandlers struct {
	Store        *postgres.Store
	SessionTTL   time.Duration
	CookieSecure bool

	// Authorization codes are short-lived; for local testing we hardcode a safe default.
	AuthCodeTTL time.Duration
}

func NewLoginHandlers(store *postgres.Store, sessionTTL time.Duration, cookieSecure bool) *LoginHandlers {
	return &LoginHandlers{
		Store:        store,
		SessionTTL:   sessionTTL,
		CookieSecure: cookieSecure,
		AuthCodeTTL:  10 * time.Minute,
	}
}

func (h *LoginHandlers) GetLogin(c *fiber.Ctx) error {
	pendingID := c.Query("pending_id", "")
	pendingSAMLID := c.Query("pending_saml_id", "")

	formAction := "/login"
	return c.Type("html").SendString(fmt.Sprintf(`<!doctype html>
<html>
<body>
  <h1>Login</h1>
  <form method="POST" action="%s">
    <label>Username <input name="username" type="text" /></label><br/>
    <label>Password <input name="password" type="password" /></label><br/>
    <input type="hidden" name="pending_id" value="%s" />
    <input type="hidden" name="pending_saml_id" value="%s" />
    <button type="submit">Sign in</button>
  </form>
</body>
</html>`, formAction, pendingID, pendingSAMLID))
}

func (h *LoginHandlers) PostLogin(c *fiber.Ctx) error {
	ctx := requestContext(c)

	username := c.FormValue("username")
	password := c.FormValue("password")
	pendingID := c.FormValue("pending_id")
	pendingSAMLID := c.FormValue("pending_saml_id")

	user, err := h.Store.GetUserByUsername(ctx, username)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).SendString("invalid credentials")
	}

	sess, err := h.Store.CreateSession(ctx, user.ID, time.Now().Add(h.SessionTTL))
	if err != nil {
		return fiber.ErrInternalServerError
	}
	session.SetSessionCookie(c, sess.SessionID, h.SessionTTL, h.CookieSecure)

	// Resume OAuth/OIDC code flow.
	if pendingID != "" {
		req, err := h.Store.ConsumePendingAuthRequest(ctx, pendingID)
		if err != nil {
			return fiber.ErrUnauthorized
		}

		code := randomToken(32)
		authCode := postgres.AuthorizationCode{
			Code:                code,
			ClientID:            req.ClientID,
			RedirectURI:         req.RedirectURI,
			CodeChallenge:       req.CodeChallenge,
			CodeChallengeMethod: req.CodeChallengeMethod,
			Scope:               req.Scope,
			Nonce:               req.Nonce,
			UserID:              user.ID,
			ExpiresAt:           time.Now().Add(h.AuthCodeTTL),
		}

		if err := h.Store.CreateAuthorizationCode(ctx, authCode); err != nil {
			return fiber.ErrInternalServerError
		}

		return c.Redirect(h.redirectWithCode(req.RedirectURI, code, req.State))
	}

	// Resume SAML flow (full response creation is implemented in the SAML todo).
	if pendingSAMLID != "" {
		return c.Redirect(fmt.Sprintf("/saml/sso?pending_saml_id=%s", url.QueryEscape(pendingSAMLID)))
	}

	return c.Redirect("/")
}

func (h *LoginHandlers) redirectWithCode(redirectURI, code, state string) string {
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

func requestContext(c *fiber.Ctx) context.Context { return c.Context() }

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// Fall back to something deterministic; only for local testing.
		return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
