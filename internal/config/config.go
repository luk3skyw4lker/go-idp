package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	ListenAddr string `env:"LISTEN_ADDR" env-default:":8080"`

	// PublicIssuerURL is the externally reachable issuer URL used in OIDC metadata + token claims.
	PublicIssuerURL string `env:"PUBLIC_ISSUER_URL" env-required:"true"`

	DatabaseURL string `env:"DATABASE_URL" env-required:"true"`

	CookieSecure bool          `env:"COOKIE_SECURE" env-default:"false"`
	SessionTTL   time.Duration `env:"SESSION_TTL" env-default:"24h"`

	JWTAccessTTL time.Duration `env:"JWT_ACCESS_TTL" env-default:"15m"`
	JWTIDTTL     time.Duration `env:"JWT_ID_TTL" env-default:"15m"`

	// DEV_KEYS_DIR controls where RSA private/public keys are stored for dev/testing.
	DevKeysDir string `env:"DEV_KEYS_DIR" env-default:"./dev-keys"`

	// Goose migration directory (relative to the working directory).
	MigrationsDir string `env:"MIGRATIONS_DIR" env-default:"./migrations"`
}

func Load() (Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

