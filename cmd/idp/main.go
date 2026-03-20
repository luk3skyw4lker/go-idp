package main

import (
	"context"
	"log"

	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/http"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

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

	log.Printf("idp listening on %s (issuer=%s)", cfg.ListenAddr, cfg.PublicIssuerURL)
	if err := app.Listen(cfg.ListenAddr); err != nil {
		log.Fatalf("listen failed: %v", err)
	}
}

