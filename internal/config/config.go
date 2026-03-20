package config

import (
	"os"
	"path/filepath"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	ListenAddr string `yaml:"listen_addr" env:"LISTEN_ADDR" env-default:":8080"`

	// PublicIssuerURL is the externally reachable issuer URL used in OIDC metadata + token claims.
	PublicIssuerURL string `yaml:"public_issuer_url" env:"PUBLIC_ISSUER_URL" env-required:"true"`

	DatabaseURL string `yaml:"database_url" env:"DATABASE_URL" env-required:"true"`

	CookieSecure bool          `yaml:"cookie_secure" env:"COOKIE_SECURE" env-default:"false"`
	SessionTTL   time.Duration `yaml:"session_ttl" env:"SESSION_TTL" env-default:"24h"`

	JWTAccessTTL time.Duration `yaml:"jwt_access_ttl" env:"JWT_ACCESS_TTL" env-default:"15m"`
	JWTIDTTL     time.Duration `yaml:"jwt_id_ttl" env:"JWT_ID_TTL" env-default:"15m"`

	// DEV_KEYS_DIR controls where RSA private/public keys are stored for dev/testing.
	DevKeysDir string `yaml:"dev_keys_dir" env:"DEV_KEYS_DIR" env-default:"./dev-keys"`

	// Goose migration directory (relative to the working directory).
	MigrationsDir string `yaml:"migrations_dir" env:"MIGRATIONS_DIR" env-default:"./migrations"`
}

type CLIConfig struct {
	DatabaseURL   string `yaml:"database_url" env:"DATABASE_URL" env-required:"true"`
	MigrationsDir string `yaml:"migrations_dir" env:"MIGRATIONS_DIR" env-default:"./migrations"`
}

func Load() (Config, error) {
	var cfg Config
	if err := readWithOptionalYAML(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func LoadCLI() (CLIConfig, error) {
	var cfg CLIConfig
	if err := readWithOptionalYAML(&cfg); err != nil {
		return CLIConfig{}, err
	}
	return cfg, nil
}

func readWithOptionalYAML(target any) error {
	if p, ok := firstExistingConfigFile(); ok {
		return cleanenv.ReadConfig(p, target)
	}
	return cleanenv.ReadEnv(target)
}

func firstExistingConfigFile() (string, bool) {
	candidates := []string{
		"config.yml",
		"config.yaml",
	}
	for _, name := range candidates {
		p := filepath.Clean(name)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
	}
	return "", false
}
