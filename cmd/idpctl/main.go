package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/luk3skyw4lker/go-idp/internal/config"
	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

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
			if err := seedClientAdd(ctx, store, cfg); err != nil {
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
			if err := seedSamlSPAdd(ctx, store, cfg); err != nil {
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

func loadCLIConfig() config.CLIConfig {
	cfg, err := config.LoadCLI()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	return cfg
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  idpctl user add --username <u> --password <p> [--display-name <d>] [--email <e>]
  idpctl client add --client-id <id> --redirect-uri <url> [--redirect-uri <url>...] [--grant-types <csv>] [--scopes <csv>] [--public] [--client-secret <s>] [--token-endpoint-auth-method <m>]
  idpctl samlsp add --issuer <entityId> --acs-url <url> [--audience-uri <uri>] [--name-id-format <format>]

Env:
  PUBLIC_ISSUER_URL (optional, used for printed integration config)
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

func seedClientAdd(ctx context.Context, store *postgres.Store, cfg config.CLIConfig) error {
	fs := flag.NewFlagSet("client add", flag.ContinueOnError)
	var clientID = fs.String("client-id", "", "client_id")
	var redirectURIs multiFlag
	fs.Var(&redirectURIs, "redirect-uri", "redirect URI (repeatable)")
	var grantTypes = fs.String("grant-types", "authorization_code,password", "comma-separated grant types")
	var scopes = fs.String("scopes", "openid", "comma-separated scopes")
	var public = fs.Bool("public", false, "public client (no client_secret; use for dev/PKCE-only flows)")
	var clientSecretPlain = fs.String("client-secret", "", "store hash of this secret instead of generating (cannot combine with --public)")
	var authMethod = fs.String("token-endpoint-auth-method", "", "token_endpoint_auth_method (default: none if --public, else client_secret_post)")
	_ = fs.Parse(os.Args[3:])

	if *clientID == "" || len(redirectURIs.values()) == 0 {
		return fmt.Errorf("client-id and at least one redirect-uri are required")
	}
	if *public && strings.TrimSpace(*clientSecretPlain) != "" {
		return fmt.Errorf("cannot use --client-secret with --public")
	}

	redirectJSONBytes, err := json.Marshal(redirectURIs.values())
	if err != nil {
		return err
	}

	var secretHash *string
	var generatedPlain string

	switch {
	case *public:
		secretHash = nil
	case strings.TrimSpace(*clientSecretPlain) != "":
		h, err := bcrypt.GenerateFromPassword([]byte(strings.TrimSpace(*clientSecretPlain)), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		s := string(h)
		secretHash = &s
	default:
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		generatedPlain = base64.RawURLEncoding.EncodeToString(raw)
		h, err := bcrypt.GenerateFromPassword([]byte(generatedPlain), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		s := string(h)
		secretHash = &s
	}

	tokenAuth := strings.TrimSpace(*authMethod)
	if tokenAuth == "" {
		if *public {
			tokenAuth = "none"
		} else {
			tokenAuth = "client_secret_post"
		}
	}

	client := postgres.Client{
		ClientID:                *clientID,
		ClientSecretHash:        secretHash,
		RedirectURIsJSON:        string(redirectJSONBytes),
		TokenEndpointAuthMethod: tokenAuth,
		AllowedGrantTypes:       splitCSV(*grantTypes),
		AllowedScopes:           splitCSV(*scopes),
	}

	if err := store.UpsertClient(ctx, client); err != nil {
		return err
	}

	fmt.Printf("client upserted: %s\n", *clientID)
	if generatedPlain != "" {
		fmt.Fprintf(os.Stderr, "\nSave this client_secret now; it will not be shown again.\n")
		fmt.Printf("client_secret=%s\n", generatedPlain)
	}
	printClientIntegrationConfig(cfg, client, generatedPlain)
	return nil
}

func seedSamlSPAdd(ctx context.Context, store *postgres.Store, cfg config.CLIConfig) error {
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
	printSAMLIntegrationConfig(cfg, sp)
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

func printClientIntegrationConfig(cfg config.CLIConfig, c postgres.Client, generatedSecret string) {
	issuer := normalizedIssuer(cfg.PublicIssuerURL)
	fmt.Println()
	fmt.Println("=== OIDC/OAuth2 consumer config ===")
	fmt.Printf("issuer: %s\n", issuer)
	fmt.Printf("authorization_endpoint: %s/authorize\n", issuer)
	fmt.Printf("token_endpoint: %s/token\n", issuer)
	fmt.Printf("jwks_uri: %s/jwks\n", issuer)
	fmt.Printf("userinfo_endpoint: %s/userinfo\n", issuer)
	fmt.Printf("client_id: %s\n", c.ClientID)
	fmt.Printf("token_endpoint_auth_method: %s\n", c.TokenEndpointAuthMethod)
	fmt.Printf("redirect_uris: %s\n", c.RedirectURIsJSON)
	fmt.Printf("allowed_grant_types: %s\n", strings.Join(c.AllowedGrantTypes, ","))
	fmt.Printf("allowed_scopes: %s\n", strings.Join(c.AllowedScopes, ","))
	if generatedSecret != "" {
		fmt.Printf("client_secret: %s\n", generatedSecret)
	} else if c.ClientSecretHash != nil && strings.TrimSpace(*c.ClientSecretHash) != "" {
		fmt.Println("client_secret: [provided by --client-secret; not printed]")
	} else {
		fmt.Println("client_secret: [public client - none]")
	}
}

func printSAMLIntegrationConfig(cfg config.CLIConfig, sp postgres.SamlSP) {
	issuer := normalizedIssuer(cfg.PublicIssuerURL)
	fmt.Println()
	fmt.Println("=== SAML SP consumer config ===")
	fmt.Printf("idp_entity_id: %s\n", issuer)
	fmt.Printf("idp_metadata_url: %s/saml/metadata\n", issuer)
	fmt.Printf("idp_sso_url: %s/saml/sso\n", issuer)
	fmt.Printf("sp_entity_id: %s\n", sp.Issuer)
	fmt.Printf("sp_acs_url: %s\n", sp.AcsURL)
	if sp.AudienceURI != nil && strings.TrimSpace(*sp.AudienceURI) != "" {
		fmt.Printf("sp_audience_uri: %s\n", *sp.AudienceURI)
	} else {
		fmt.Println("sp_audience_uri: [not set]")
	}
	if sp.NameIDFormat != nil && strings.TrimSpace(*sp.NameIDFormat) != "" {
		fmt.Printf("name_id_format: %s\n", *sp.NameIDFormat)
	}
}

func normalizedIssuer(issuer string) string {
	i := strings.TrimSpace(issuer)
	if i == "" {
		return "http://localhost:8080"
	}
	return strings.TrimRight(i, "/")
}
