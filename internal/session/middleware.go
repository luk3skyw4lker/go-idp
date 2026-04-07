package session

import (
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
)

const SessionCookieName = "idp_session"

type MiddlewareOptions struct {
	Store        *postgres.Store
	SessionTTL   time.Duration
	CookieSecure bool
}

// Middleware attaches "user_id" to the Fiber context if a valid session cookie is present.
// Unauthenticated requests continue without error (endpoints decide whether auth is required).
func Middleware(opts MiddlewareOptions) fiber.Handler {
	return func(c fiber.Ctx) error {
		if opts.Store == nil {
			return fiber.ErrInternalServerError
		}

		sessionID := c.Cookies(SessionCookieName)
		if sessionID == "" {
			return c.Next()
		}

		ctx := c.Context()
		sess, err := opts.Store.GetSession(ctx, sessionID)
		if err != nil {
			// Invalid/expired session: treat as unauthenticated.
			return c.Next()
		}

		_ = opts.Store.UpdateSessionLastSeen(ctx, sess.SessionID)
		c.Locals("user_id", sess.UserID)
		return c.Next()
	}
}

func SetSessionCookie(c fiber.Ctx, sessionID string, ttl time.Duration, cookieSecure bool) {
	c.Cookie(&fiber.Cookie{
		Name:     SessionCookieName,
		Value:    sessionID,
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		HTTPOnly: true,
		Secure:   cookieSecure,
		SameSite: "Lax",
	})
}

func ClearSessionCookie(c fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		HTTPOnly: true,
		Secure:   false,
		SameSite: "Lax",
	})
}

func UserIDFromContext(c fiber.Ctx) (string, bool) {
	v := c.Locals("user_id")
	if v == nil {
		return "", false
	}
	userID, ok := v.(string)
	return userID, ok
}
