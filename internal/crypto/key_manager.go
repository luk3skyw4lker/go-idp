package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/luk3skyw4lker/go-idp/internal/storage/postgres"
)

type KeyManager struct {
	store      *postgres.Store
	devKeysDir string
	keyBits    int
}

func NewKeyManager(store *postgres.Store, devKeysDir string) *KeyManager {
	return &KeyManager{
		store:      store,
		devKeysDir: devKeysDir,
		keyBits:    3072,
	}
}

// EnsureActiveKey returns the currently active RSA keypair, generating a new one if needed.
func (km *KeyManager) EnsureActiveKey(ctx context.Context) (*rsa.PrivateKey, *rsa.PublicKey, postgres.SigningKeyMeta, error) {
	meta, err := km.store.GetActiveSigningKey(ctx)
	if err == nil {
		priv, pub, loadErr := km.loadKeyPair(meta)
		if loadErr == nil {
			return priv, pub, meta, nil
		}

		// If metadata exists but files are missing/corrupt, recover by creating a new key.
		slog.Warn("active signing key invalid; generating replacement",
			"kid", meta.Kid,
			"private_pem_path", meta.PrivatePemPath,
			"public_pem_path", meta.PublicPemPath,
			"error", loadErr.Error(),
		)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// No active key yet: generate one and activate.
	} else {
		// If GetActiveSigningKey itself failed (other than no rows), abort.
		if err != nil {
			return nil, nil, postgres.SigningKeyMeta{}, err
		}
	}

	priv, pub, kid, privatePath, publicPath, err := km.generateKeyPair()
	if err != nil {
		return nil, nil, postgres.SigningKeyMeta{}, err
	}

	meta = postgres.SigningKeyMeta{
		Kid:            kid,
		Active:         false,
		PrivatePemPath: privatePath,
		PublicPemPath:  publicPath,
	}
	if err := km.store.CreateSigningKeyMeta(ctx, meta); err != nil {
		return nil, nil, postgres.SigningKeyMeta{}, err
	}
	if err := km.store.SetActiveSigningKey(ctx, kid); err != nil {
		return nil, nil, postgres.SigningKeyMeta{}, err
	}
	meta.Active = true

	return priv, pub, meta, nil
}

func (km *KeyManager) loadKeyPair(meta postgres.SigningKeyMeta) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privPemBytes, err := os.ReadFile(meta.PrivatePemPath)
	if err != nil {
		return nil, nil, err
	}
	pubPemBytes, err := os.ReadFile(meta.PublicPemPath)
	if err != nil {
		return nil, nil, err
	}

	block, _ := pem.Decode(privPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode private PEM for kid=%s", meta.Kid)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		parsedAny, errPKCS8 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if errPKCS8 != nil {
			return nil, nil, fmt.Errorf("parse private key for kid=%s: %w", meta.Kid, err)
		}
		rsaPriv, ok := parsedAny.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected private key type for kid=%s", meta.Kid)
		}
		priv = rsaPriv
	}

	block, _ = pem.Decode(pubPemBytes)
	if block == nil {
		return nil, nil, fmt.Errorf("failed to decode public PEM for kid=%s", meta.Kid)
	}

	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		parsedPub, errPKIX := x509.ParsePKIXPublicKey(block.Bytes)
		if errPKIX != nil {
			return nil, nil, fmt.Errorf("parse public key for kid=%s: %w", meta.Kid, err)
		}
		rsaPub, ok := parsedPub.(*rsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("unexpected RSA public key type for kid=%s", meta.Kid)
		}
		pub = rsaPub
	}

	return priv, pub, nil
}

func (km *KeyManager) generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, string, string, string, error) {
	if err := os.MkdirAll(km.devKeysDir, 0o750); err != nil {
		return nil, nil, "", "", "", err
	}

	priv, err := rsa.GenerateKey(rand.Reader, km.keyBits)
	if err != nil {
		return nil, nil, "", "", "", err
	}
	pub := &priv.PublicKey

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, "", "", "", err
	}
	sum := sha256.Sum256(pubDER)
	kid := hex.EncodeToString(sum[:8])

	privatePath := filepath.Join(km.devKeysDir, fmt.Sprintf("%s_private.pem", kid))
	publicPath := filepath.Join(km.devKeysDir, fmt.Sprintf("%s_public.pem", kid))

	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})
	pubBytes := x509.MarshalPKCS1PublicKey(pub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})

	// Write key files with restrictive perms (dev/testing).
	if err := os.WriteFile(privatePath, privPEM, 0o600); err != nil {
		return nil, nil, "", "", "", err
	}
	if err := os.WriteFile(publicPath, pubPEM, 0o644); err != nil {
		return nil, nil, "", "", "", err
	}

	return priv, pub, kid, privatePath, publicPath, nil
}
