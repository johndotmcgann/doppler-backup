package crypto

import "testing"

// testParams uses a much smaller N than DefaultParams so the test suite
// doesn't pay real scrypt work-factor cost on every DeriveKey call.
var testParams = Params{N: 1 << 4, R: 8, P: 1}

func TestGenerateSalt(t *testing.T) {
	a, err := GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if len(a) != SaltLen {
		t.Fatalf("expected salt of length %d, got %d", SaltLen, len(a))
	}
	b, err := GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	if string(a) == string(b) {
		t.Fatalf("expected two generated salts to differ")
	}
}

func TestDeriveKey(t *testing.T) {
	salt := []byte("0123456789abcdef")

	k1, err := DeriveKey("correct horse", salt, testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(k1))
	}

	k2, err := DeriveKey("correct horse", salt, testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatalf("expected same passphrase+salt to derive the same key")
	}

	k3, err := DeriveKey("different passphrase", salt, testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	if string(k1) == string(k3) {
		t.Fatalf("expected different passphrase to derive a different key")
	}

	k4, err := DeriveKey("correct horse", []byte("fedcba9876543210"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	if string(k1) == string(k4) {
		t.Fatalf("expected different salt to derive a different key")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := DeriveKey("passphrase", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	plaintext := []byte(`{"SECRET":"value"}`)

	nonce, ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	got, err := Decrypt(key, nonce, ciphertext)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("expected round-tripped plaintext %q, got %q", plaintext, got)
	}
}

func TestEncryptNoncesAreUnique(t *testing.T) {
	key, err := DeriveKey("passphrase", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	nonce1, _, err := Encrypt(key, []byte("plaintext"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	nonce2, _, err := Encrypt(key, []byte("plaintext"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if string(nonce1) == string(nonce2) {
		t.Fatalf("expected two nonces from separate Encrypt calls to differ")
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	key1, err := DeriveKey("passphrase-one", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	key2, err := DeriveKey("passphrase-two", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	nonce, ciphertext, err := Encrypt(key1, []byte("plaintext"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(key2, nonce, ciphertext); err == nil {
		t.Fatalf("expected decrypt with wrong key to fail")
	}
}

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	key, err := DeriveKey("passphrase", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	nonce, ciphertext, err := Encrypt(key, []byte("plaintext"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0xFF

	if _, err := Decrypt(key, nonce, tampered); err == nil {
		t.Fatalf("expected decrypt with tampered ciphertext to fail")
	}
}

func TestDecryptTamperedNonceFails(t *testing.T) {
	key, err := DeriveKey("passphrase", []byte("0123456789abcdef"), testParams)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	nonce, ciphertext, err := Encrypt(key, []byte("plaintext"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	tampered := append([]byte(nil), nonce...)
	tampered[0] ^= 0xFF

	if _, err := Decrypt(key, tampered, ciphertext); err == nil {
		t.Fatalf("expected decrypt with tampered nonce to fail")
	}
}

func TestDefaultParamsStrongerThanScryptInteractiveDefault(t *testing.T) {
	params := DefaultParams()
	if params.N <= 1<<15 {
		t.Fatalf("expected N stronger than scrypt's 2009 interactive default (1<<15), got %d", params.N)
	}
}

func TestInvalidKeyLengthErrors(t *testing.T) {
	badKey := []byte("too-short")

	if _, _, err := Encrypt(badKey, []byte("plaintext")); err == nil {
		t.Fatalf("expected encrypt with invalid key length to error")
	}
	if _, err := Decrypt(badKey, make([]byte, nonceLen), []byte("ciphertext")); err == nil {
		t.Fatalf("expected decrypt with invalid key length to error")
	}
}
