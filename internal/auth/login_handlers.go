package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v3"
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

func (h *LoginHandlers) GetLogin(c fiber.Ctx) error {
	pendingID := c.Query("pending_id", "")
	pendingSAMLID := c.Query("pending_saml_id", "")

	formAction := "/login"
	return c.Type("html").SendString(fmt.Sprintf(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Sign in</title>
  <style>
    :root {
      --bg: #f3f6ff;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #64748b;
      --brand: #2563eb;
      --brand-dark: #1d4ed8;
      --border: #dbe4ff;
      --shadow: 0 12px 40px rgba(37, 99, 235, 0.16);
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif;
      color: var(--text);
      background:
        radial-gradient(1000px 420px at 10%% -10%%, #dbeafe, transparent 70%%),
        radial-gradient(900px 460px at 100%% 100%%, #e0e7ff, transparent 70%%),
        var(--bg);
      display: grid;
      place-items: center;
      padding: 24px;
    }
    .card {
      width: 100%%;
      max-width: 420px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 22px;
      box-shadow: var(--shadow);
      padding: 28px;
      animation: cardEnter 420ms cubic-bezier(.2,.8,.2,1);
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 10px;
    }
    .brand h1 {
      margin: 0;
      font-size: 1.1rem;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    .subtitle {
      margin: 0 0 20px;
      color: var(--muted);
      font-size: 0.95rem;
    }
    .gopher {
      width: 44px;
      height: 44px;
      border-radius: 12px;
      background: linear-gradient(145deg, #60a5fa, #3b82f6);
      display: grid;
      place-items: center;
      box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.25);
      animation: floatGopher 3.2s ease-in-out infinite;
    }
    .field {
      display: grid;
      gap: 8px;
      margin-bottom: 14px;
    }
    label {
      font-size: 0.88rem;
      color: #334155;
      font-weight: 600;
    }
    input[type="text"],
    input[type="password"] {
      width: 100%%;
      border: 1px solid #cbd5e1;
      background: #fff;
      border-radius: 14px;
      padding: 12px 14px;
      font-size: 0.95rem;
      outline: none;
      transition: border-color .2s ease, box-shadow .2s ease, transform .2s ease;
    }
    input:focus {
      border-color: #93c5fd;
      box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.15);
      transform: translateY(-1px);
    }
    button {
      width: 100%%;
      margin-top: 6px;
      border: 0;
      border-radius: 14px;
      padding: 12px 16px;
      background: linear-gradient(180deg, var(--brand), var(--brand-dark));
      color: #fff;
      font-weight: 700;
      letter-spacing: 0.2px;
      cursor: pointer;
      transition: transform .18s ease, filter .18s ease, box-shadow .18s ease;
    }
    button:hover {
      filter: brightness(1.02);
      transform: translateY(-1px);
      box-shadow: 0 8px 20px rgba(37, 99, 235, 0.25);
    }
    button:active {
      transform: translateY(0);
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.22);
    }
    @keyframes cardEnter {
      from { opacity: 0; transform: translateY(10px) scale(0.985); }
      to { opacity: 1; transform: translateY(0) scale(1); }
    }
    @keyframes floatGopher {
      0%%, 100%% { transform: translateY(0); }
      50%% { transform: translateY(-3px); }
    }
    @media (prefers-reduced-motion: reduce) {
      .card, .gopher, input, button {
        animation: none !important;
        transition: none !important;
      }
    }
  </style>
</head>
<body>
  <main class="card">
    <div class="brand">
      <div class="gopher" aria-hidden="true">
        <svg width="28" height="28" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
          <circle cx="32" cy="34" r="18" fill="#86D0F2"/>
          <circle cx="24" cy="30" r="6" fill="#fff"/>
          <circle cx="40" cy="30" r="6" fill="#fff"/>
          <circle cx="24" cy="30" r="2.4" fill="#0F172A"/>
          <circle cx="40" cy="30" r="2.4" fill="#0F172A"/>
          <ellipse cx="32" cy="41" rx="7" ry="4.5" fill="#E6EEF3"/>
          <circle cx="32" cy="41" r="1.6" fill="#0F172A"/>
          <rect x="22" y="17" width="6" height="6" rx="3" fill="#86D0F2"/>
          <rect x="36" y="17" width="6" height="6" rx="3" fill="#86D0F2"/>
        </svg>
      </div>
      <h1>GoIdP</h1>
    </div>
    <p class="subtitle">Sign in to continue</p>
    <form method="POST" action="%s">
      <div class="field">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" autocomplete="username" required />
      </div>
      <div class="field">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password" required />
      </div>
      <input type="hidden" name="pending_id" value="%s" />
      <input type="hidden" name="pending_saml_id" value="%s" />
      <button type="submit">Sign in</button>
    </form>
  </main>
</body>
</html>`, formAction, pendingID, pendingSAMLID))
}

func (h *LoginHandlers) PostLogin(c fiber.Ctx) error {
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

		return c.Redirect().To(h.redirectWithCode(req.RedirectURI, code, req.State))
	}

	// Resume SAML flow (full response creation is implemented in the SAML todo).
	if pendingSAMLID != "" {
		return c.Redirect().To(fmt.Sprintf("/saml/sso?pending_saml_id=%s", url.QueryEscape(pendingSAMLID)))
	}

	return c.Redirect().To("/")
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

func requestContext(c fiber.Ctx) context.Context { return c }

func randomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		// Fall back to something deterministic; only for local testing.
		return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
