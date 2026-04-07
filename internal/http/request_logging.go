package http

import (
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/requestid"
)

// requestLogger logs request input and final response in structured JSON format.
// Sensitive values are redacted.
func requestLogger() fiber.Handler {
	return func(c fiber.Ctx) error {
		start := time.Now()

		reqID := requestid.FromContext(c)
		if reqID == "" {
			reqID = c.Get(fiber.HeaderXRequestID)
		}

		query := redactValues(parseQuery(string(c.Request().URI().QueryString())))
		body := redactFormBody(c)

		slog.Info("http_request",
			"request_id", reqID,
			"method", c.Method(),
			"path", c.Path(),
			"query", query,
			"content_type", c.Get(fiber.HeaderContentType),
			"body", body,
			"remote_ip", c.IP(),
		)

		err := c.Next()

		status := c.Response().StatusCode()
		if status == 0 {
			status = fiber.StatusOK
		}

		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}

		slog.Log(c, level, "http_response",
			"request_id", reqID,
			"method", c.Method(),
			"path", c.Path(),
			"status", status,
			"latency_ms", time.Since(start).Milliseconds(),
			"response_bytes", len(c.Response().Body()),
			"has_error", err != nil,
		)

		return err
	}
}

func parseQuery(raw string) url.Values {
	if raw == "" {
		return url.Values{}
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return url.Values{}
	}
	return v
}

func redactFormBody(c fiber.Ctx) url.Values {
	ct := strings.ToLower(c.Get(fiber.HeaderContentType))
	if !strings.Contains(ct, fiber.MIMEApplicationForm) {
		return url.Values{}
	}
	v, err := url.ParseQuery(string(c.Body()))
	if err != nil {
		return url.Values{}
	}
	return redactValues(v)
}

func redactValues(v url.Values) url.Values {
	out := url.Values{}
	for k, values := range v {
		if shouldRedactKey(k) {
			out[k] = []string{"[REDACTED]"}
			continue
		}
		out[k] = values
	}
	return out
}

func shouldRedactKey(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "password", "client_secret", "access_token", "refresh_token", "id_token", "samlresponse":
		return true
	default:
		return false
	}
}
