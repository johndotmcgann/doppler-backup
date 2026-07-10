// Package store persists encrypted secret snapshots in SQLite. Callers are
// responsible for encryption/decryption; this package only ever sees
// ciphertext.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

type Snapshot struct {
	ID         int64
	Project    string
	Config     string
	TakenAt    time.Time
	Nonce      []byte
	Ciphertext []byte
}

type Store struct {
	db *sql.DB
}

// KDFParams holds the scrypt work-factor parameters a database's KDF salt
// was created with. Store persists these alongside the salt but has no
// opinion on what they mean cryptographically - that's internal/crypto's
// job.
type KDFParams struct {
	N, R, P int
}

// Open opens (creating if necessary) the SQLite database at path, ensures
// its schema exists, and locks the file down to owner-only permissions.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("restrict database permissions: %w", err)
	}
	return s, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS meta (
			id       INTEGER PRIMARY KEY CHECK (id = 1),
			kdf_salt BLOB NOT NULL,
			kdf_n    INTEGER NOT NULL DEFAULT 32768,
			kdf_r    INTEGER NOT NULL DEFAULT 8,
			kdf_p    INTEGER NOT NULL DEFAULT 1
		);
		CREATE TABLE IF NOT EXISTS snapshots (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			project    TEXT NOT NULL,
			config     TEXT NOT NULL,
			taken_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			nonce      BLOB NOT NULL,
			ciphertext BLOB NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_snapshots_project_config
			ON snapshots(project, config, taken_at);
	`)
	if err != nil {
		return fmt.Errorf("migrate schema: %w", err)
	}
	// Databases created before kdf_n/kdf_r/kdf_p existed have a meta table
	// without them; CREATE TABLE IF NOT EXISTS above is a no-op there, so
	// add the columns explicitly. The DEFAULT above matches the scrypt
	// parameters those older databases were actually created with (scrypt's
	// 2009 "interactive" defaults), so existing keys keep re-deriving
	// correctly.
	return s.addMissingKDFColumns()
}

func (s *Store) addMissingKDFColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(meta)`)
	if err != nil {
		return fmt.Errorf("inspect meta schema: %w", err)
	}
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notNull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notNull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("read meta schema: %w", err)
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate meta schema: %w", err)
	}
	rows.Close()

	for _, col := range []struct{ name, ddl string }{
		{"kdf_n", `ALTER TABLE meta ADD COLUMN kdf_n INTEGER NOT NULL DEFAULT 32768`},
		{"kdf_r", `ALTER TABLE meta ADD COLUMN kdf_r INTEGER NOT NULL DEFAULT 8`},
		{"kdf_p", `ALTER TABLE meta ADD COLUMN kdf_p INTEGER NOT NULL DEFAULT 1`},
	} {
		if have[col.name] {
			continue
		}
		if _, err := s.db.Exec(col.ddl); err != nil {
			return fmt.Errorf("add %s column: %w", col.name, err)
		}
	}
	return nil
}

// readSalt returns the database's stored KDF salt and parameters, or
// sql.ErrNoRows if none has been stored yet.
func (s *Store) readSalt() ([]byte, KDFParams, error) {
	var salt []byte
	var params KDFParams
	err := s.db.QueryRow(`SELECT kdf_salt, kdf_n, kdf_r, kdf_p FROM meta WHERE id = 1`).
		Scan(&salt, &params.N, &params.R, &params.P)
	if err != nil {
		return nil, KDFParams{}, err
	}
	return salt, params, nil
}

// EnsureSalt returns the database's KDF salt and the parameters it was
// derived under, generating and persisting a new salt under defaultParams
// on first use so every subsequent run derives the same key from a given
// passphrase.
func (s *Store) EnsureSalt(generate func() ([]byte, error), defaultParams KDFParams) ([]byte, KDFParams, error) {
	salt, params, err := s.readSalt()
	if err == nil {
		return salt, params, nil
	}
	if err != sql.ErrNoRows {
		return nil, KDFParams{}, fmt.Errorf("read kdf salt: %w", err)
	}
	salt, err = generate()
	if err != nil {
		return nil, KDFParams{}, err
	}
	if _, err := s.db.Exec(
		`INSERT INTO meta (id, kdf_salt, kdf_n, kdf_r, kdf_p) VALUES (1, ?, ?, ?, ?)`,
		salt, defaultParams.N, defaultParams.R, defaultParams.P,
	); err != nil {
		return nil, KDFParams{}, fmt.Errorf("store kdf salt: %w", err)
	}
	return salt, defaultParams, nil
}

// CurrentSalt returns the database's KDF salt and parameters, or an error if
// none has been stored yet (i.e. backup has never run against this
// database).
func (s *Store) CurrentSalt() ([]byte, KDFParams, error) {
	salt, params, err := s.readSalt()
	if err == sql.ErrNoRows {
		return nil, KDFParams{}, fmt.Errorf("no backups exist yet; nothing to rotate")
	}
	if err != nil {
		return nil, KDFParams{}, fmt.Errorf("read kdf salt: %w", err)
	}
	return salt, params, nil
}

// RotateKey re-encrypts every snapshot and replaces the stored KDF salt and
// parameters inside a single transaction: either every row and the salt
// update succeed, or none of them do. reencrypt is called once per snapshot
// and must return the new nonce/ciphertext for newSalt's key.
func (s *Store) RotateKey(newSalt []byte, newParams KDFParams, reencrypt func(Snapshot) (nonce, ciphertext []byte, err error)) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin rotation: %w", err)
	}

	rows, err := tx.Query(`SELECT id, project, config, taken_at, nonce, ciphertext FROM snapshots`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("read snapshots: %w", err)
	}
	var snaps []Snapshot
	for rows.Next() {
		var snap Snapshot
		if err := rows.Scan(&snap.ID, &snap.Project, &snap.Config, &snap.TakenAt, &snap.Nonce, &snap.Ciphertext); err != nil {
			rows.Close()
			tx.Rollback()
			return 0, fmt.Errorf("read snapshot row: %w", err)
		}
		snaps = append(snaps, snap)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		tx.Rollback()
		return 0, fmt.Errorf("iterate snapshots: %w", err)
	}
	rows.Close()

	for _, snap := range snaps {
		nonce, ciphertext, err := reencrypt(snap)
		if err != nil {
			tx.Rollback()
			return 0, fmt.Errorf("rotate snapshot %d (%s/%s): %w", snap.ID, snap.Project, snap.Config, err)
		}
		if _, err := tx.Exec(`UPDATE snapshots SET nonce = ?, ciphertext = ? WHERE id = ?`, nonce, ciphertext, snap.ID); err != nil {
			tx.Rollback()
			return 0, fmt.Errorf("update snapshot %d: %w", snap.ID, err)
		}
	}

	if _, err := tx.Exec(
		`UPDATE meta SET kdf_salt = ?, kdf_n = ?, kdf_r = ?, kdf_p = ? WHERE id = 1`,
		newSalt, newParams.N, newParams.R, newParams.P,
	); err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("update kdf salt: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit rotation: %w", err)
	}
	return len(snaps), nil
}

// SaveSnapshot inserts a new encrypted snapshot row for project/config.
func (s *Store) SaveSnapshot(project, config string, nonce, ciphertext []byte) error {
	_, err := s.db.Exec(
		`INSERT INTO snapshots (project, config, nonce, ciphertext) VALUES (?, ?, ?, ?)`,
		project, config, nonce, ciphertext,
	)
	if err != nil {
		return fmt.Errorf("save snapshot for %s/%s: %w", project, config, err)
	}
	return nil
}

// LatestSnapshot returns the most recent snapshot for project/config, or nil
// if none exists.
func (s *Store) LatestSnapshot(project, config string) (*Snapshot, error) {
	row := s.db.QueryRow(`
		SELECT id, project, config, taken_at, nonce, ciphertext
		FROM snapshots
		WHERE project = ? AND config = ?
		ORDER BY taken_at DESC
		LIMIT 1`, project, config)
	return scanSnapshot(row)
}

// GetSnapshot returns the snapshot with the given id, or nil if none exists.
func (s *Store) GetSnapshot(id int64) (*Snapshot, error) {
	row := s.db.QueryRow(`
		SELECT id, project, config, taken_at, nonce, ciphertext
		FROM snapshots
		WHERE id = ?`, id)
	return scanSnapshot(row)
}

func scanSnapshot(row *sql.Row) (*Snapshot, error) {
	var snap Snapshot
	err := row.Scan(&snap.ID, &snap.Project, &snap.Config, &snap.TakenAt, &snap.Nonce, &snap.Ciphertext)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}
	return &snap, nil
}

// ListSnapshots returns snapshots newest-first, optionally filtered to a
// single project.
func (s *Store) ListSnapshots(project string) ([]Snapshot, error) {
	var rows *sql.Rows
	var err error
	if project == "" {
		rows, err = s.db.Query(`
			SELECT id, project, config, taken_at, nonce, ciphertext
			FROM snapshots ORDER BY taken_at DESC`)
	} else {
		rows, err = s.db.Query(`
			SELECT id, project, config, taken_at, nonce, ciphertext
			FROM snapshots WHERE project = ? ORDER BY taken_at DESC`, project)
	}
	if err != nil {
		return nil, fmt.Errorf("list snapshots: %w", err)
	}
	defer rows.Close()

	var snaps []Snapshot
	for rows.Next() {
		var snap Snapshot
		if err := rows.Scan(&snap.ID, &snap.Project, &snap.Config, &snap.TakenAt, &snap.Nonce, &snap.Ciphertext); err != nil {
			return nil, fmt.Errorf("read snapshot row: %w", err)
		}
		snaps = append(snaps, snap)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate snapshots: %w", err)
	}
	return snaps, nil
}
