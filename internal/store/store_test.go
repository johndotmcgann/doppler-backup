package store

import (
	"errors"
	"os"
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

func TestEnsureSaltGeneratesOnceAndPersists(t *testing.T) {
	st := openTestStore(t)

	calls := 0
	generate := func() ([]byte, error) {
		calls++
		return []byte("generated-salt-0"), nil
	}

	first, err := st.EnsureSalt(generate)
	if err != nil {
		t.Fatalf("ensure salt (first): %v", err)
	}
	second, err := st.EnsureSalt(generate)
	if err != nil {
		t.Fatalf("ensure salt (second): %v", err)
	}

	if calls != 1 {
		t.Fatalf("expected generate to be called once, got %d calls", calls)
	}
	if string(first) != string(second) {
		t.Fatalf("expected same salt across calls: first=%q second=%q", first, second)
	}
}

func TestCurrentSaltErrorsWhenNoneStored(t *testing.T) {
	st := openTestStore(t)

	if _, err := st.CurrentSalt(); err == nil {
		t.Fatalf("expected error when no salt has been stored yet")
	}
}

func TestGetSnapshotReturnsNilWhenMissing(t *testing.T) {
	st := openTestStore(t)

	snap, err := st.GetSnapshot(12345)
	if err != nil {
		t.Fatalf("get snapshot: %v", err)
	}
	if snap != nil {
		t.Fatalf("expected nil snapshot for missing id, got %+v", snap)
	}
}

func TestLatestSnapshotReturnsNilWhenMissing(t *testing.T) {
	st := openTestStore(t)

	snap, err := st.LatestSnapshot("proj", "dev")
	if err != nil {
		t.Fatalf("latest snapshot: %v", err)
	}
	if snap != nil {
		t.Fatalf("expected nil snapshot for missing project/config, got %+v", snap)
	}
}

func TestSaveAndGetSnapshot(t *testing.T) {
	st := openTestStore(t)

	if err := st.SaveSnapshot("proj", "dev", []byte("nonce1"), []byte("cipher1")); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	latest, err := st.LatestSnapshot("proj", "dev")
	if err != nil {
		t.Fatalf("latest snapshot: %v", err)
	}
	if latest == nil {
		t.Fatalf("expected a snapshot, got nil")
	}
	if latest.Project != "proj" || latest.Config != "dev" {
		t.Fatalf("unexpected snapshot: %+v", latest)
	}
	if string(latest.Nonce) != "nonce1" || string(latest.Ciphertext) != "cipher1" {
		t.Fatalf("unexpected snapshot payload: %+v", latest)
	}

	byID, err := st.GetSnapshot(latest.ID)
	if err != nil {
		t.Fatalf("get snapshot: %v", err)
	}
	if byID == nil || byID.ID != latest.ID {
		t.Fatalf("expected get snapshot to return same row as latest, got %+v", byID)
	}
}

func TestListSnapshotsFiltersByProject(t *testing.T) {
	st := openTestStore(t)

	if err := st.SaveSnapshot("proj-a", "dev", []byte("n1"), []byte("c1")); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	if err := st.SaveSnapshot("proj-b", "dev", []byte("n2"), []byte("c2")); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	all, err := st.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots (all): %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 snapshots total, got %d", len(all))
	}

	filtered, err := st.ListSnapshots("proj-a")
	if err != nil {
		t.Fatalf("list snapshots (filtered): %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("expected 1 snapshot for proj-a, got %d", len(filtered))
	}
	if filtered[0].Project != "proj-a" {
		t.Fatalf("expected snapshot for proj-a, got %+v", filtered[0])
	}
}

func TestOpenRestrictsFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perms.db")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected db file permissions 0o600, got %o", perm)
	}
}
