// Package crypto encrypts secret snapshots at rest using a passphrase-derived
// AES-256-GCM key, so the SQLite database never stores plaintext secrets.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	SaltLen  = 16
	nonceLen = 12
	keyLen   = 32
)

// Params holds the scrypt work-factor parameters used to derive a key from a
// passphrase. A database persists the Params it was created with alongside
// its salt, so DefaultParams can be strengthened over time without breaking
// decryption of snapshots created under older, weaker defaults.
type Params struct {
	N, R, P int
}

// DefaultParams returns the scrypt parameters used for newly created
// databases. N=1<<15 was scrypt's original 2009 "interactive" (per-request)
// default; this KDF instead runs at most once per CLI invocation, so a
// higher work factor is free in practice.
func DefaultParams() Params {
	return Params{N: 1 << 17, R: 8, P: 1}
}

// GenerateSalt returns a fresh random salt, stored once per database and
// reused to derive the encryption key from the passphrase on every run.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

// DeriveKey derives a 32-byte AES key from the passphrase and salt via
// scrypt, using params (the ones stored alongside the salt, so a given
// database always re-derives under whatever work factor it was created
// with).
func DeriveKey(passphrase string, salt []byte, params Params) ([]byte, error) {
	key, err := scrypt.Key([]byte(passphrase), salt, params.N, params.R, params.P, keyLen)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	return key, nil
}

// Encrypt seals plaintext with AES-256-GCM under key, returning a fresh
// random nonce alongside the ciphertext.
func Encrypt(key, plaintext []byte) (nonce, ciphertext []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt opens ciphertext with AES-256-GCM under key and nonce. A non-nil
// error means either the passphrase is wrong or the data is corrupted -
// GCM's authentication tag makes those the only two possibilities.
func Decrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("incorrect passphrase or corrupted snapshot")
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm, nil
}
