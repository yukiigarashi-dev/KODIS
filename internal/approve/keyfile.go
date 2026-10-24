package approve

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	privatePEMType = "PRIVATE KEY"
	publicPEMType  = "PUBLIC KEY"
	maxKeyFileSize = 16 << 10
)

// DefaultKeyPath is where the approver private key lives by default.
func DefaultKeyPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "kodis", "approver.key"), nil
}

// WritePrivateKey writes priv as PKCS#8 PEM with mode 0600. It never
// overwrites an existing file.
func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	return writeNew(path, pem.EncodeToMemory(&pem.Block{Type: privatePEMType, Bytes: der}), 0o600)
}

// WritePublicKey writes pub as PKIX PEM with mode 0644. It never
// overwrites an existing file.
func WritePublicKey(path string, pub ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return err
	}
	return writeNew(path, pem.EncodeToMemory(&pem.Block{Type: publicPEMType, Bytes: der}), 0o644)
}

func writeNew(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(data)
	return err
}

// LoadPrivateKey reads a private key, refusing files that are not regular,
// are symlinks, are accessible by group or others, or are owned by another
// user.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := readKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	der, err := decodePEM(data, privatePEMType)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ed25519 private key", path)
	}
	return priv, nil
}

// LoadPublicKey reads a PKIX PEM ed25519 public key.
func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readKeyFile(path, false)
	if err != nil {
		return nil, err
	}
	der, err := decodePEM(data, publicPEMType)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s: not an ed25519 public key", path)
	}
	return pub, nil
}

// readKeyFile opens without following symlinks and checks the opened
// file itself, so the checks and the read cannot refer to different files.
func readKeyFile(path string, private bool) ([]byte, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if private {
		if perm := fi.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("%s: permissions %04o allow group/other access, want 0600", path, perm)
		}
		if err := checkOwner(fi); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFileSize {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxKeyFileSize)
	}
	return data, nil
}

func decodePEM(data []byte, typ string) ([]byte, error) {
	b, rest := pem.Decode(data)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	if b.Type != typ {
		return nil, fmt.Errorf("PEM type %q, want %q", b.Type, typ)
	}
	if len(b.Headers) != 0 {
		return nil, errors.New("PEM headers are not supported")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("trailing data after PEM block")
	}
	return b.Bytes, nil
}
