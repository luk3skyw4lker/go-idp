package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
	"github.com/ilyakaznacheev/cleanenv"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type cliConfig struct {
	DatabaseURL   string `env:"DATABASE_URL" env-required:"true"`
	MigrationsDir string `env:"MIGRATIONS_DIR" env-default:"./migrations"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cfg := loadCLIConfig()
	ctx := context.Background()

	dbPool, err := postgres.NewPoolFromURL(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db connect error: %v\n", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	if err := postgres.Migrate(ctx, dbPool, cfg.MigrationsDir); err != nil {
		fmt.Fprintf(os.Stderr, "migrations error: %v\n", err)
		os.Exit(1)
	}

	store := postgres.NewStore(dbPool)

	switch os.Args[1] {
	case "user":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "add":
			if err := seedUserAdd(ctx, dbPool); err != nil {
				fmt.Fprintf(os.Stderr, "user add error: %v\n", err)
				os.Exit(1)
			}
		default:
			usage()
			os.Exit(2)
		}
	case "client":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "add":
			if err := seedClientAdd(ctx, store); err != nil {
				fmt.Fprintf(os.Stderr, "client add error: %v\n", err)
				os.Exit(1)
			}
		default:
			usage()
			os.Exit(2)
		}
	case "samlsp":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "add":
			if err := seedSamlSPAdd(ctx, store); err != nil {
				fmt.Fprintf(os.Stderr, "samlsp add error: %v\n", err)
				os.Exit(1)
			}
		default:
			usage()
			os.Exit(2)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func loadCLIConfig() cliConfig {
	var cfg cliConfig
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  idpctl user add --username <u> --password <p> [--display-name <d>] [--email <e>]
  idpctl client add --client-id <id> --redirect-uri <url> [--redirect-uri <url>...] [--grant-types <csv>] [--scopes <csv>]
  idpctl samlsp add --issuer <entityId> --acs-url <url> [--audience-uri <uri>] [--name-id-format <format>]

Env:
  DATABASE_URL (required)
  MIGRATIONS_DIR (optional, default ./migrations)
`)
}

func seedUserAdd(ctx context.Context, pool *pgxpool.Pool) error {
	// Use a new FlagSet so we don't clobber os.Args parsing.
	fs := flag.NewFlagSet("user add", flag.ContinueOnError)
	var username = fs.String("username", "", "username")
	var password = fs.String("password", "", "password")
	var displayName = fs.String("display-name", "", "display name")
	var email = fs.String("email", "", "email")
	_ = fs.Parse(os.Args[3:])

	if *username == "" || *password == "" {
		return fmt.Errorf("username and password are required")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	_, err = pool.Exec(
		ctx,
		`INSERT INTO users (username, password_hash, display_name, email)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (username)
		 DO UPDATE SET
		   password_hash=EXCLUDED.password_hash,
		   display_name=EXCLUDED.display_name,
		   email=EXCLUDED.email`,
		*username,
		string(hash),
		*displayName,
		*email,
	)
	if err != nil {
		return err
	}

	fmt.Printf("user upserted: %s\n", *username)
	return nil
}

func seedClientAdd(ctx context.Context, store *postgres.Store) error {
	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	var clientID = fs.String("client-id", "", "client_id")
	var redirectURIs multiFlag
	fs.Var(&redirectURIs, "redirect-uri", "redirect URI (repeatable)")
	var grantTypes = fs.String("grant-types", "authorization_code,password", "comma-separated grant types")
	var scopes = fs.String("scopes", "openid", "comma-separated scopes")
	var authMethod = fs.String("token-endpoint-auth-method", "none", "token_endpoint_auth_method")
	_ = fs.Parse(os.Args[3:])

	if *clientID == "" || len(redirectURIs.values()) == 0 {
		return fmt.Errorf("client-id and at least one redirect-uri are required")
	}

	redirectJSONBytes, err := json.Marshal(redirectURIs.values())
	if err != nil {
		return err
	}

	client := postgres.Client{
		ClientID:                *clientID,
		ClientSecretHash:        nil, // public / testing clients
		RedirectURIsJSON:        string(redirectJSONBytes),
		TokenEndpointAuthMethod: *authMethod,
		AllowedGrantTypes:       splitCSV(*grantTypes),
		AllowedScopes:           splitCSV(*scopes),
	}

	if err := store.UpsertClient(ctx, client); err != nil {
		return err
	}

	fmt.Printf("client upserted: %s\n", *clientID)
	return nil
}

func seedSamlSPAdd(ctx context.Context, store *postgres.Store) error {
	fs := flag.NewFlagSet("samlsp add", flag.ContinueOnError)
	var issuer = fs.String("issuer", "", "SP EntityID")
	var acsURL = fs.String("acs-url", "", "SP ACS URL (HTTP-POST)")
	var audienceURI = fs.String("audience-uri", "", "audience restriction URI (optional)")
	var nameIDFormat = fs.String("name-id-format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified", "NameID format")
	_ = fs.Parse(os.Args[3:])

	if *issuer == "" || *acsURL == "" {
		return fmt.Errorf("issuer and acs-url are required")
	}

	var audPtr *string
	if strings.TrimSpace(*audienceURI) != "" {
		audPtr = audienceURI
	}

	var nameIDPtr *string
	if strings.TrimSpace(*nameIDFormat) != "" {
		nameIDPtr = nameIDFormat
	}

	sp := postgres.SamlSP{
		Issuer:       *issuer,
		AcsURL:       *acsURL,
		AudienceURI:  audPtr,
		NameIDFormat: nameIDPtr,
	}

	if err := store.UpsertSamlSP(ctx, sp); err != nil {
		return err
	}

	fmt.Printf("saml SP upserted: %s\n", *issuer)
	return nil
}

type multiFlag struct {
	valuesList []string
}

func (m *multiFlag) String() string { return strings.Join(m.valuesList, ",") }
func (m *multiFlag) Set(v string) error {
	m.valuesList = append(m.valuesList, v)
	return nil
}
func (m *multiFlag) values() []string { return m.valuesList }
func (m *multiFlag) Len() int         { return len(m.valuesList) }

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
