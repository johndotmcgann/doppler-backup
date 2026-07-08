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
			kdf_salt BLOB NOT NULL
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
	return nil
}

// EnsureSalt returns the database's KDF salt, generating and persisting one
// on first use so every subsequent run derives the same key from a given
// passphrase.
func (s *Store) EnsureSalt(generate func() ([]byte, error)) ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow(`SELECT kdf_salt FROM meta WHERE id = 1`).Scan(&salt)
	if err == nil {
		return salt, nil
	}
	if err != sql.ErrNoRows {
		return nil, fmt.Errorf("read kdf salt: %w", err)
	}
	salt, err = generate()
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`INSERT INTO meta (id, kdf_salt) VALUES (1, ?)`, salt); err != nil {
		return nil, fmt.Errorf("store kdf salt: %w", err)
	}
	return salt, nil
}

// CurrentSalt returns the database's KDF salt, or an error if none has been
// stored yet (i.e. backup has never run against this database).
func (s *Store) CurrentSalt() ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow(`SELECT kdf_salt FROM meta WHERE id = 1`).Scan(&salt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no backups exist yet; nothing to rotate")
	}
	if err != nil {
		return nil, fmt.Errorf("read kdf salt: %w", err)
	}
	return salt, nil
}

// RotateKey re-encrypts every snapshot and replaces the stored KDF salt
// inside a single transaction: either every row and the salt update
// succeed, or none of them do. reencrypt is called once per snapshot and
// must return the new nonce/ciphertext for newSalt's key.
func (s *Store) RotateKey(newSalt []byte, reencrypt func(Snapshot) (nonce, ciphertext []byte, err error)) (int, error) {
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

	if _, err := tx.Exec(`UPDATE meta SET kdf_salt = ? WHERE id = 1`, newSalt); err != nil {
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
