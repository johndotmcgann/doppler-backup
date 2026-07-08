package store

import (
	"errors"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestRotateKeyReencryptsAndUpdatesSalt(t *testing.T) {
	st := openTestStore(t)

	oldSalt, err := st.EnsureSalt(func() ([]byte, error) { return []byte("old-salt-0123456"), nil })
	if err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", []byte("nonce1"), []byte("cipher1")); err != nil {
		t.Fatalf("save snapshot 1: %v", err)
	}
	if err := st.SaveSnapshot("proj", "prd", []byte("nonce2"), []byte("cipher2")); err != nil {
		t.Fatalf("save snapshot 2: %v", err)
	}

	newSalt := []byte("new-salt-0123456")
	n, err := st.RotateKey(newSalt, func(snap Snapshot) ([]byte, []byte, error) {
		if string(snap.Nonce) != "nonce1" && string(snap.Nonce) != "nonce2" {
			t.Fatalf("unexpected snapshot passed to reencrypt: %+v", snap)
		}
		return append(snap.Nonce, '-', 'r'), append(snap.Ciphertext, '-', 'r'), nil
	})
	if err != nil {
		t.Fatalf("rotate key: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 snapshots rotated, got %d", n)
	}

	gotSalt, err := st.CurrentSalt()
	if err != nil {
		t.Fatalf("current salt: %v", err)
	}
	if string(gotSalt) != string(newSalt) {
		t.Fatalf("salt not updated: got %q, want %q", gotSalt, newSalt)
	}
	if string(gotSalt) == string(oldSalt) {
		t.Fatalf("salt unexpectedly unchanged")
	}

	snaps, err := st.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	for _, snap := range snaps {
		if string(snap.Nonce) != "nonce1-r" && string(snap.Nonce) != "nonce2-r" {
			t.Fatalf("snapshot %d not re-encrypted: nonce=%q", snap.ID, snap.Nonce)
		}
	}
}

func TestRotateKeyRollsBackOnError(t *testing.T) {
	st := openTestStore(t)

	if _, err := st.EnsureSalt(func() ([]byte, error) { return []byte("old-salt-0123456"), nil }); err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", []byte("nonce1"), []byte("cipher1")); err != nil {
		t.Fatalf("save snapshot 1: %v", err)
	}
	if err := st.SaveSnapshot("proj", "prd", []byte("nonce2"), []byte("cipher2")); err != nil {
		t.Fatalf("save snapshot 2: %v", err)
	}

	calls := 0
	wantErr := errors.New("boom")
	_, err := st.RotateKey([]byte("new-salt-0123456"), func(snap Snapshot) ([]byte, []byte, error) {
		calls++
		if calls == 2 {
			return nil, nil, wantErr
		}
		return append(snap.Nonce, '-', 'r'), append(snap.Ciphertext, '-', 'r'), nil
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}

	snaps, err := st.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	for _, snap := range snaps {
		if string(snap.Nonce) != "nonce1" && string(snap.Nonce) != "nonce2" {
			t.Fatalf("snapshot %d was modified despite rollback: nonce=%q", snap.ID, snap.Nonce)
		}
	}
}
