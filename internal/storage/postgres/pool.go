package postgres

import (
	"context"

	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewPool(ctx context.Context, cfg config.Config) (*pgxpool.Pool, error) {
	pool, err := NewPoolFromURL(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}

	return pool, nil
}

func NewPoolFromURL(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	return pgxpool.New(ctx, databaseURL)
}

