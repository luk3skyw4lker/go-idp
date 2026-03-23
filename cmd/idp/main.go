package main

import (
	"context"
	"log"
	"log/slog"
	"os"
	"strings"

	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/http"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}
	configureLogger(cfg)

	ctx := context.Background()
	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
		log.Fatalf("db pool error: %v", err)
	}
	defer pool.Close()

	if err := postgres.Migrate(ctx, pool, cfg.MigrationsDir); err != nil {
		log.Fatalf("migration error: %v", err)
	}

	store := postgres.NewStore(pool)
	app := http.NewApp(cfg, store)

	slog.Info("server_starting",
		"listen_addr", cfg.ListenAddr,
		"issuer", cfg.PublicIssuerURL,
		"log_level", strings.ToLower(strings.TrimSpace(cfg.LogLevel)),
		"log_format", strings.ToLower(strings.TrimSpace(cfg.LogFormat)),
	)
	if err := app.Listen(cfg.ListenAddr); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
}

func configureLogger(cfg config.Config) {
	level := parseLogLevel(cfg.LogLevel)
	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.LogAddSource,
	}

	switch strings.ToLower(strings.TrimSpace(cfg.LogFormat)) {
	case "text":
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, opts)))
	default:
		slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, opts)))
	}
}

func parseLogLevel(v string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

