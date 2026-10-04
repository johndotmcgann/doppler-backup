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
	"unicode/utf8"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/johndotmcgann/doppler-backup/internal/crypto"
	"github.com/johndotmcgann/doppler-backup/internal/doppler"
	"github.com/johndotmcgann/doppler-backup/internal/store"
)

// Version is set at build time via -ldflags "-X main.Version=<git tag>".
var Version = "dev"

// minPassphraseLength is the floor enforced on passphrases used to encrypt
// new data (backup, rotate's new passphrase). This passphrase is fed
// directly into scrypt and protects a static SQLite file that an attacker
// with a copy can brute-force fully offline, with no rate limiting or
// lockout — a materially worse threat model than an online login password
// (which is what NIST 800-63B's 8-character floor is calibrated for), so a
// longer floor is warranted here. Per current guidance, length rather than
// character-class complexity is what matters for resisting offline
// brute-force, so no uppercase/digit/symbol rules are enforced. This floor
// works alongside crypto.DefaultParams' scrypt N=1<<17, which adds
// per-guess cost on top of it.
const minPassphraseLength = 12

// validatePassphraseStrength enforces minPassphraseLength on passphrases
// that will be used to encrypt new data. It is deliberately not applied to
// passphrases used only to decrypt existing data, since a database may
// have been created before this floor existed.
func validatePassphraseStrength(pass string) error {
	n := utf8.RuneCountInString(pass)
	if n < minPassphraseLength {
		return fmt.Errorf(
			"passphrase must be at least %d characters (got %d) — length, not complexity, "+
				"is what protects against offline brute force; use a long random passphrase "+
				"from a password manager, or a multi-word Diceware-style phrase",
			minPassphraseLength, n)
	}
	return nil
}

// errPassphraseRequired reports that no passphrase was given and stdin
// isn't a terminal to prompt on, so the caller must pass flagName
// explicitly (e.g. for cron/unattended use).
func errPassphraseRequired(flagName string) error {
	return fmt.Errorf(
		"no passphrase given and stdin is not a terminal (e.g. running under cron): "+
			"pass %s explicitly for unattended use", flagName)
}

// dopplerClient is the subset of *doppler.Client used by the run* functions
// below. It exists so tests can substitute a fake implementation instead of
// shelling out to the real doppler CLI.
type dopplerClient interface {
	ListProjects() ([]doppler.Project, error)
	ListConfigs(project string) ([]doppler.Config, error)
	DownloadSecrets(project, config string) (map[string]string, error)
	UploadSecrets(project, config, path string) error
	Version() (string, error)
}

// checkDopplerVersion verifies the doppler CLI on PATH meets
// doppler.MinVersion before backup/restore does any other work, so a
// too-old CLI fails fast with a clear message instead of a confusing
// JSON-parse error later.
func checkDopplerVersion(client dopplerClient) error {
	v, err := client.Version()
	if err != nil {
		return err
	}
	return doppler.CheckMinVersion(v)
}

func main() {
	var dbPath string
	root := &cobra.Command{
		Use:           "doppler-backup",
		Short:         "Emergency backup/restore for Doppler secrets, snapshotted to an encrypted local SQLite database",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dbPath, "db", "./doppler-backup.db", "path to the SQLite backup database")

	root.AddCommand(newBackupCmd(&dbPath), newRestoreCmd(&dbPath), newListCmd(&dbPath), newRotateCmd(&dbPath))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// noopValidate accepts any passphrase, used for passphrases that only
// decrypt existing data (see resolvePassphrase).
func noopValidate(string) error { return nil }

// resolveWithPrompt returns flagValue, after validate, if set. Otherwise,
// if stdin is a terminal, it prompts interactively without echoing input,
// rejects a blank entry, and validates the result too. If stdin isn't a
// terminal (e.g. cron) and no flag was given, it errors rather than
// prompting. If confirmLabel is non-empty, prompting asks a second time
// under that label and requires the two entries to match, guarding against
// a typo locking the database; this only applies to the prompt path, since
// a flag value has no separate confirmation to compare against.
func resolveWithPrompt(flagValue, promptLabel, flagName string, validate func(string) error, confirmLabel string) (string, error) {
	if flagValue != "" {
		if err := validate(flagValue); err != nil {
			return "", err
		}
		return flagValue, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errPassphraseRequired(flagName)
	}
	pass, err := readPassword(promptLabel)
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", fmt.Errorf("passphrase must not be blank")
	}
	if err := validate(pass); err != nil {
		return "", err
	}
	if confirmLabel == "" {
		return pass, nil
	}
	confirm, err := readPassword(confirmLabel)
	if err != nil {
		return "", err
	}
	if pass != confirm {
		return "", fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}

// resolvePassphrase resolves a passphrase used only to decrypt existing
// data. It deliberately does not enforce minPassphraseLength, because the
// database may have been created under a shorter passphrase before length
// enforcement existed.
func resolvePassphrase(flagValue, promptLabel, flagName string) (string, error) {
	return resolveWithPrompt(flagValue, promptLabel, flagName, noopValidate, "")
}

// resolveEncryptPassphrase behaves like resolvePassphrase, but is used for
// passphrases that will encrypt new data (backup), so it additionally
// enforces minPassphraseLength on both the flag and the prompt path.
func resolveEncryptPassphrase(flagValue, promptLabel, flagName string) (string, error) {
	return resolveWithPrompt(flagValue, promptLabel, flagName, validatePassphraseStrength, "")
}

// resolveNewPassphrase behaves like resolveEncryptPassphrase, except when
// prompting interactively it asks for the new passphrase twice and requires
// the two entries to match, guarding against a typo locking the database.
func resolveNewPassphrase(flagValue string) (string, error) {
	return resolveWithPrompt(flagValue, "New passphrase", "--new-passphrase", validatePassphraseStrength, "Confirm new passphrase")
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

func newBackupCmd(dbPath *string) *cobra.Command {
	var project, passphrase string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Snapshot secrets for all projects (or one, with --project) into the backup database",
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := resolveEncryptPassphrase(passphrase, "Passphrase", "--passphrase")
			if err != nil {
				return err
			}
			return runBackup(*dbPath, project, pass)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "limit backup to a single project (default: all projects)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to encrypt secrets at rest — required (min 12 characters); prompts interactively if omitted, or pass this flag explicitly for non-interactive/cron use")
	return cmd
}

func runBackup(dbPath, project, passphrase string) error {
	return runBackupWithClient(doppler.NewClient(), dbPath, project, passphrase)
}

// openStoreAndKey opens the backup database at dbPath and derives the
// AES key for passphrase from its (ensuring-if-absent) KDF salt. On error
// the store is closed before returning.
func openStoreAndKey(dbPath, passphrase string) (*store.Store, []byte, error) {
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

func runBackupWithClient(client dopplerClient, dbPath, project, passphrase string) error {
	if err := checkDopplerVersion(client); err != nil {
		return err
	}

	st, key, err := openStoreAndKey(dbPath, passphrase)
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

func newRestoreCmd(dbPath *string) *cobra.Command {
	var project, config, passphrase string
	var snapshotID int64
	cmd := &cobra.Command{
		Use:   "restore",
		Short: "Restore a project/config's secrets from the most recent (or a specific) snapshot",
		RunE: func(cmd *cobra.Command, args []string) error {
			pass, err := resolvePassphrase(passphrase, "Passphrase", "--passphrase")
			if err != nil {
				return err
			}
			return runRestore(*dbPath, project, config, pass, snapshotID)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project to restore into (required)")
	cmd.Flags().StringVar(&config, "config", "", "config to restore into (required)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to decrypt the snapshot — required; prompts interactively if omitted, or pass this flag explicitly for non-interactive/cron use")
	cmd.Flags().Int64Var(&snapshotID, "snapshot", 0, "specific snapshot id to restore (default: latest for project/config)")
	cmd.MarkFlagRequired("project")
	cmd.MarkFlagRequired("config")
	return cmd
}

func runRestore(dbPath, project, config, passphrase string, snapshotID int64) error {
	return runRestoreWithClient(doppler.NewClient(), dbPath, project, config, passphrase, snapshotID)
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

// createPlaintextTemp creates the decrypted-secrets temp file in dir,
// preferring the memory-backed directory from plaintextTempDir. A tmpfs
// that exists can still be unusable — read-only, full, or mounted with
// restrictive permissions in a container or CI sandbox — so if creating
// there fails we retry once against the OS default temp dir instead of
// aborting the restore over a plaintext-location preference.
func createPlaintextTemp(dir string) (*os.File, error) {
	f, err := os.CreateTemp(dir, "doppler-backup-*.json")
	if err != nil && dir != "" {
		return os.CreateTemp("", "doppler-backup-*.json")
	}
	return f, err
}

func runRestoreWithClient(client dopplerClient, dbPath, project, config, passphrase string, snapshotID int64) error {
	if err := checkDopplerVersion(client); err != nil {
		return err
	}

	st, key, err := openStoreAndKey(dbPath, passphrase)
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

	tmp, err := createPlaintextTemp(plaintextTempDir())
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

func newListCmd(dbPath *string) *cobra.Command {
	var project string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List stored snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runList(*dbPath, project)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "limit to a single project")
	return cmd
}

func runList(dbPath, project string) error {
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

func newRotateCmd(dbPath *string) *cobra.Command {
	var oldPassphrase, newPassphrase string
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Re-encrypt every snapshot under a new passphrase, invalidating the old one",
		RunE: func(cmd *cobra.Command, args []string) error {
			oldPass, err := resolvePassphrase(oldPassphrase, "Current passphrase", "--old-passphrase")
			if err != nil {
				return err
			}
			newPass, err := resolveNewPassphrase(newPassphrase)
			if err != nil {
				return err
			}
			return runRotate(*dbPath, oldPass, newPass)
		},
	}
	cmd.Flags().StringVar(&oldPassphrase, "old-passphrase", "", "current passphrase used to decrypt existing snapshots — required; prompts interactively if omitted, or pass this flag explicitly for non-interactive/cron use")
	cmd.Flags().StringVar(&newPassphrase, "new-passphrase", "", "new passphrase to re-encrypt snapshots with — required (min 12 characters); prompts interactively with confirmation if omitted, or pass this flag explicitly for non-interactive/cron use")
	return cmd
}

func runRotate(dbPath, oldPassphrase, newPassphrase string) error {
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
