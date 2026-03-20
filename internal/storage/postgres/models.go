package postgres

import "time"

type User struct {
	ID           string
	Username     string
	PasswordHash string
	DisplayName string
	Email        string
	CreatedAt    time.Time
}

type Client struct {
	ClientID               string
	ClientSecretHash      *string
	RedirectURIsJSON       string
	TokenEndpointAuthMethod string
	AllowedGrantTypes     []string
	AllowedScopes          []string
}

type Session struct {
	SessionID   string
	UserID      string
	ExpiresAt   time.Time
	LastSeenAt time.Time
}

