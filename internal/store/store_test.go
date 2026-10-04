package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

var testKDFParams = KDFParams{N: legacyScryptN, R: legacyScryptR, P: legacyScryptP}

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

	oldSalt, _, err := st.EnsureSalt(func() ([]byte, error) { return []byte("old-salt-0123456"), nil }, testKDFParams)
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
	n, err := st.RotateKey(newSalt, testKDFParams, func(snap Snapshot) ([]byte, []byte, error) {
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

	gotSalt, gotParams, err := st.CurrentSalt()
	if err != nil {
		t.Fatalf("current salt: %v", err)
	}
	if gotParams != testKDFParams {
		t.Fatalf("params not updated: got %+v, want %+v", gotParams, testKDFParams)
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

	if _, _, err := st.EnsureSalt(func() ([]byte, error) { return []byte("old-salt-0123456"), nil }, testKDFParams); err != nil {
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
	_, err := st.RotateKey([]byte("new-salt-0123456"), testKDFParams, func(snap Snapshot) ([]byte, []byte, error) {
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

	first, _, err := st.EnsureSalt(generate, testKDFParams)
	if err != nil {
		t.Fatalf("ensure salt (first): %v", err)
	}
	second, _, err := st.EnsureSalt(generate, testKDFParams)
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

	if _, _, err := st.CurrentSalt(); err == nil {
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

func TestOpenMigratesPreKDFParamsDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-schema.db")

	// Simulate a database created before kdf_n/kdf_r/kdf_p existed: a meta
	// table with only kdf_salt, populated the way EnsureSalt used to.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw db: %v", err)
	}
	if _, err := raw.Exec(`
		CREATE TABLE meta (
			id       INTEGER PRIMARY KEY CHECK (id = 1),
			kdf_salt BLOB NOT NULL
		);
		INSERT INTO meta (id, kdf_salt) VALUES (1, ?);
	`, []byte("legacy-salt-01234")); err != nil {
		t.Fatalf("seed legacy meta row: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw db: %v", err)
	}

	st, err := Open(path)
	if err != nil {
		t.Fatalf("open store on legacy schema: %v", err)
	}
	defer st.Close()

	salt, params, err := st.CurrentSalt()
	if err != nil {
		t.Fatalf("current salt: %v", err)
	}
	if string(salt) != "legacy-salt-01234" {
		t.Fatalf("expected preserved legacy salt, got %q", salt)
	}
	want := KDFParams{N: legacyScryptN, R: legacyScryptR, P: legacyScryptP}
	if params != want {
		t.Fatalf("expected legacy scrypt defaults backfilled as %+v, got %+v", want, params)
	}
}

// TestOpenNeverCreatesFileUnderLoosePermissions guards against the file
// being briefly created under the process umask (e.g. world-readable)
// before being locked down to 0600 — Open must create it at 0600 from the
// start rather than creating then chmod'ing.
func TestOpenNeverCreatesFileUnderLoosePermissions(t *testing.T) {
	old := syscall.Umask(0o002)
	defer syscall.Umask(old)

	path := filepath.Join(t.TempDir(), "perm.db")
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
		t.Fatalf("expected db file permissions 0o600 even under a permissive umask, got %o", perm)
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

func TestOpenSetsBusyTimeout(t *testing.T) {
	st := openTestStore(t)

	var got int
	if err := st.db.QueryRow(`PRAGMA busy_timeout`).Scan(&got); err != nil {
		t.Fatalf("read busy_timeout: %v", err)
	}
	if got != busyTimeoutMS {
		t.Fatalf("expected busy_timeout %d, got %d", busyTimeoutMS, got)
	}
}

// TestConcurrentWriteWaitsForLock covers an overlapping run (e.g. cron
// firing while the previous backup is still writing): with SQLite's default
// busy handler the second writer fails immediately with SQLITE_BUSY, so Open
// must set a busy timeout and let it wait for the first writer to commit.
func TestConcurrentWriteWaitsForLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent.db")
	first, err := Open(path)
	if err != nil {
		t.Fatalf("open first store: %v", err)
	}
	defer first.Close()
	second, err := Open(path)
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	defer second.Close()

	// Hold the write lock with an uncommitted transaction.
	tx, err := first.db.Begin()
	if err != nil {
		t.Fatalf("begin transaction: %v", err)
	}
	if _, err := tx.Exec(
		`INSERT INTO snapshots (project, config, nonce, ciphertext) VALUES ('proj', 'dev', 'n1', 'c1')`,
	); err != nil {
		tx.Rollback()
		t.Fatalf("insert while holding write lock: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- second.SaveSnapshot("proj", "prd", []byte("n2"), []byte("c2"))
	}()

	select {
	case err := <-done:
		t.Fatalf("expected concurrent write to wait for the lock, got early return: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("concurrent write after lock released: %v", err)
		}
	case <-time.After(busyTimeoutMS * time.Millisecond):
		t.Fatalf("concurrent write did not complete after the lock was released")
	}

	snaps, err := second.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected both snapshots to be present, got %d", len(snaps))
	}
}
