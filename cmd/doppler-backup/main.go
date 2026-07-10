package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/mcgannj/doppler-backup/internal/crypto"
	"github.com/mcgannj/doppler-backup/internal/doppler"
	"github.com/mcgannj/doppler-backup/internal/store"
)

// Version is set at build time via -ldflags "-X main.Version=<git tag>".
var Version = "dev"

var dbPath string

// defaultPassphrase is used when no --passphrase flag is given and the user
// enters nothing at the interactive prompt.
const defaultPassphrase = "doppler_backup"

// dopplerClient is the subset of *doppler.Client used by the run* functions
// below. It exists so tests can substitute a fake implementation instead of
// shelling out to the real doppler CLI.
type dopplerClient interface {
	ListProjects() ([]doppler.Project, error)
	ListConfigs(project string) ([]doppler.Config, error)
	DownloadSecrets(project, config string) (map[string]string, error)
	UploadSecrets(project, config, path string) error
}

func main() {
	root := &cobra.Command{
		Use:           "doppler-backup",
		Short:         "Emergency backup/restore for Doppler secrets, snapshotted to an encrypted local SQLite database",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dbPath, "db", "./doppler-backup.db", "path to the SQLite backup database")

	root.AddCommand(newBackupCmd(), newRestoreCmd(), newListCmd(), newRotateCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// resolvePassphrase returns flagValue if set. Otherwise, if stdin is a
// terminal, it prompts interactively without echoing input; an empty entry
// (or a non-interactive stdin, e.g. cron) falls back to defaultPassphrase.
func resolvePassphrase(flagValue, promptLabel string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultPassphrase, nil
	}
	pass, err := readPassword(promptLabel + " (blank for default)")
	if err != nil {
		return "", err
	}
	if pass == "" {
		return defaultPassphrase, nil
	}
	return pass, nil
}

// resolveNewPassphrase behaves like resolvePassphrase, except when prompting
// interactively it asks for the new passphrase twice and requires the two
// entries to match, guarding against a typo locking the database.
func resolveNewPassphrase(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return defaultPassphrase, nil
	}
	first, err := readPassword("New passphrase (blank for default)")
	if err != nil {
		return "", err
	}
	if first == "" {
		return defaultPassphrase, nil
	}
	confirm, err := readPassword("Confirm new passphrase")
	if err != nil {
		return "", err
	}
	if first != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return first, nil
}

// readPassword prompts label on stderr and reads a line from stdin without
// echoing it back to the terminal.
func readPassword(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(b), nil
}

func newBackupCmd() *cobra.Command {
	var project, passphrase string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Snapshot secrets for all projects (or one, with --project) into the backup database",
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := resolvePassphrase(passphrase, "Passphrase")
			if err != nil {
				return err
			}
			return runBackup(project, pass)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "limit backup to a single project (default: all projects)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to encrypt secrets at rest (prompts interactively if omitted; defaults to \"doppler_backup\" if left blank)")
	return cmd
}

func runBackup(project, passphrase string) error {
	return runBackupWithClient(doppler.NewClient(), project, passphrase)
}

// openStoreAndKey opens the backup database at dbPath and derives the
// AES key for passphrase from its (ensuring-if-absent) KDF salt. On error
// the store is closed before returning.
func openStoreAndKey(passphrase string) (*store.Store, []byte, error) {
	st, err := store.Open(dbPath)
	if err != nil {
		return nil, nil, err
	}
	salt, params, err := st.EnsureSalt(crypto.GenerateSalt, store.KDFParams(crypto.DefaultParams()))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	key, err := crypto.DeriveKey(passphrase, salt, crypto.Params(params))
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	return st, key, nil
}

func runBackupWithClient(client dopplerClient, project, passphrase string) error {
	st, key, err := openStoreAndKey(passphrase)
	if err != nil {
		return err
	}
	defer st.Close()

	var projects []doppler.Project
	if project != "" {
		projects = []doppler.Project{{Name: project}}
	} else {
		projects, err = client.ListProjects()
		if err != nil {
			return err
		}
	}

	var snapshotted, failed int
	for _, p := range projects {
		configs, err := client.ListConfigs(p.Name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping project %s: %v\n", p.Name, err)
			failed++
			continue
		}
		for _, c := range configs {
			if err := backupOne(st, client, key, p.Name, c.Name); err != nil {
				fmt.Fprintf(os.Stderr, "skipping %s/%s: %v\n", p.Name, c.Name, err)
				failed++
				continue
			}
			fmt.Printf("backed up %s/%s\n", p.Name, c.Name)
			snapshotted++
		}
	}

	fmt.Printf("done: %d config(s) backed up, %d failed\n", snapshotted, failed)
	if failed > 0 && snapshotted == 0 {
		return fmt.Errorf("all backups failed")
	}
	return nil
}

func backupOne(st *store.Store, client dopplerClient, key []byte, project, config string) error {
	secrets, err := client.DownloadSecrets(project, config)
	if err != nil {
		return err
	}
	plaintext, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("encode secrets: %w", err)
	}
	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return err
	}
	return st.SaveSnapshot(project, config, nonce, ciphertext)
}

func newRestoreCmd() *cobra.Command {
	var project, config, passphrase string
	var snapshotID int64
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a project/config's secrets from the most recent (or a specific) snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := resolvePassphrase(passphrase, "Passphrase")
			if err != nil {
				return err
			}
			return runRestore(project, config, pass, snapshotID)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project to restore into (required)")
	cmd.Flags().StringVar(&config, "config", "", "config to restore into (required)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to decrypt the snapshot (prompts interactively if omitted; defaults to \"doppler_backup\" if left blank)")
	cmd.Flags().Int64Var(&snapshotID, "snapshot", 0, "specific snapshot id to restore (default: latest for project/config)")
	cmd.MarkFlagRequired("project")
	cmd.MarkFlagRequired("config")
	return cmd
}

func runRestore(project, config, passphrase string, snapshotID int64) error {
	return runRestoreWithClient(doppler.NewClient(), project, config, passphrase, snapshotID)
}

// plaintextTempDir returns a memory-backed directory (tmpfs) for the
// decrypted-secrets temp file used by restore, so the plaintext never
// touches disk. Falls back to the OS default temp dir (which may or may
// not be tmpfs) when none is available.
func plaintextTempDir() string {
	if info, err := os.Stat("/dev/shm"); err == nil && info.IsDir() {
		return "/dev/shm"
	}
	return ""
}

func runRestoreWithClient(client dopplerClient, project, config, passphrase string, snapshotID int64) error {
	st, key, err := openStoreAndKey(passphrase)
	if err != nil {
		return err
	}
	defer st.Close()

	var snap *store.Snapshot
	if snapshotID != 0 {
		snap, err = st.GetSnapshot(snapshotID)
	} else {
		snap, err = st.LatestSnapshot(project, config)
	}
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("no snapshot found for %s/%s", project, config)
	}

	plaintext, err := crypto.Decrypt(key, snap.Nonce, snap.Ciphertext)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(plaintextTempDir(), "doppler-backup-*.json")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())

	// Best-effort cleanup on SIGINT/SIGTERM: deferred cleanup above doesn't
	// run if the process is killed mid-restore, leaving decrypted secrets
	// on disk. This narrows that window but can't catch SIGKILL.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
			os.Remove(tmp.Name())
			os.Exit(1)
		case <-done:
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(done)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("restrict temp file permissions: %w", err)
	}
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := client.UploadSecrets(project, config, tmp.Name()); err != nil {
		return err
	}

	fmt.Printf("restored snapshot %d (%s) into %s/%s\n", snap.ID, snap.TakenAt.Format("2006-01-02 15:04:05"), project, config)
	return nil
}

func newListCmd() *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(project)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "limit to a single project")
	return cmd
}

func runList(project string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	snaps, err := st.ListSnapshots(project)
	if err != nil {
		return err
	}
	if len(snaps) == 0 {
		fmt.Println("no snapshots found")
		return nil
	}
	fmt.Printf("%-6s %-30s %-15s %s\n", "ID", "PROJECT", "CONFIG", "TAKEN AT (UTC)")
	for _, s := range snaps {
		fmt.Printf("%-6d %-30s %-15s %s\n", s.ID, s.Project, s.Config, s.TakenAt.Format("2006-01-02 15:04:05"))
	}
	return nil
}

func newRotateCmd() *cobra.Command {
	var oldPassphrase, newPassphrase string
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Re-encrypt every snapshot under a new passphrase, invalidating the old one",
		RunE: func(cmd *cobra.Command, args []string) error {
			oldPass, err := resolvePassphrase(oldPassphrase, "Current passphrase")
			if err != nil {
				return err
			}
			newPass, err := resolveNewPassphrase(newPassphrase)
			if err != nil {
				return err
			}
			return runRotate(oldPass, newPass)
		},
	}
	cmd.Flags().StringVar(&oldPassphrase, "old-passphrase", "", "current passphrase used to decrypt existing snapshots (prompts interactively if omitted; defaults to \"doppler_backup\" if left blank)")
	cmd.Flags().StringVar(&newPassphrase, "new-passphrase", "", "new passphrase to re-encrypt snapshots with (prompts interactively if omitted, with confirmation; defaults to \"doppler_backup\" if left blank)")
	return cmd
}

func runRotate(oldPassphrase, newPassphrase string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	oldSalt, oldParams, err := st.CurrentSalt()
	if err != nil {
		return err
	}
	oldKey, err := crypto.DeriveKey(oldPassphrase, oldSalt, crypto.Params(oldParams))
	if err != nil {
		return err
	}

	backupPath, err := copyFile(dbPath)
	if err != nil {
		return fmt.Errorf("back up database before rotation: %w", err)
	}

	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return err
	}
	newParams := crypto.DefaultParams()
	newKey, err := crypto.DeriveKey(newPassphrase, newSalt, newParams)
	if err != nil {
		return err
	}

	n, err := st.RotateKey(newSalt, store.KDFParams(newParams), func(snap store.Snapshot) (nonce, ciphertext []byte, err error) {
		plaintext, err := crypto.Decrypt(oldKey, snap.Nonce, snap.Ciphertext)
		if err != nil {
			return nil, nil, err
		}
		return crypto.Encrypt(newKey, plaintext)
	})
	if err != nil {
		return err
	}

	fmt.Printf("rotated %d snapshot(s); previous database preserved at %s\n", n, backupPath)
	return nil
}

// copyFile copies path to path + ".bak-<unix timestamp>" with owner-only
// permissions, and returns the new path.
func copyFile(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer src.Close()

	dstPath := path + ".bak-" + strconv.FormatInt(time.Now().Unix(), 10)
	dst, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create %s: %w", dstPath, err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copy %s to %s: %w", path, dstPath, err)
	}
	return dstPath, nil
}
