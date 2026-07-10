package main

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/mcgannj/doppler-backup/internal/crypto"
	"github.com/mcgannj/doppler-backup/internal/doppler"
	"github.com/mcgannj/doppler-backup/internal/store"
)

// setTestDB points the package-level dbPath at a fresh temp file for the
// duration of the test.
func setTestDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	prev := dbPath
	dbPath = path
	t.Cleanup(func() { dbPath = prev })
	return path
}

// fakeClient implements dopplerClient with scripted responses.
type fakeClient struct {
	projects           []doppler.Project
	listProjectsErr    error
	configsByProject   map[string][]doppler.Config
	listConfigsErr     map[string]error
	secretsByKey       map[string]map[string]string
	downloadSecretsErr map[string]error
	uploadedProject    string
	uploadedConfig     string
	uploadedContent    []byte
	uploadedPath       string
	uploadErr          error
}

func (f *fakeClient) ListProjects() ([]doppler.Project, error) {
	if f.listProjectsErr != nil {
		return nil, f.listProjectsErr
	}
	return f.projects, nil
}

func (f *fakeClient) ListConfigs(project string) ([]doppler.Config, error) {
	if err, ok := f.listConfigsErr[project]; ok {
		return nil, err
	}
	return f.configsByProject[project], nil
}

func (f *fakeClient) DownloadSecrets(project, config string) (map[string]string, error) {
	key := project + "/" + config
	if err, ok := f.downloadSecretsErr[key]; ok {
		return nil, err
	}
	return f.secretsByKey[key], nil
}

func (f *fakeClient) UploadSecrets(project, config, path string) error {
	if f.uploadErr != nil {
		return f.uploadErr
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.uploadedProject = project
	f.uploadedConfig = config
	f.uploadedContent = content
	f.uploadedPath = path
	return nil
}

func TestRunBackupWithClientAllProjects(t *testing.T) {
	setTestDB(t)

	client := &fakeClient{
		projects: []doppler.Project{{Name: "proj-a"}, {Name: "proj-b"}},
		configsByProject: map[string][]doppler.Config{
			"proj-a": {{Name: "dev"}},
			"proj-b": {{Name: "prd"}},
		},
		secretsByKey: map[string]map[string]string{
			"proj-a/dev": {"KEY": "val-a"},
			"proj-b/prd": {"KEY": "val-b"},
		},
	}

	if err := runBackupWithClient(client, "", "passphrase"); err != nil {
		t.Fatalf("run backup: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	snaps, err := st.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(snaps))
	}
}

func TestRunBackupWithClientSingleProjectSkipsListProjects(t *testing.T) {
	setTestDB(t)

	client := &fakeClient{
		listProjectsErr: errors.New("ListProjects should not be called when --project is set"),
		configsByProject: map[string][]doppler.Config{
			"proj-a": {{Name: "dev"}},
		},
		secretsByKey: map[string]map[string]string{
			"proj-a/dev": {"KEY": "val"},
		},
	}

	if err := runBackupWithClient(client, "proj-a", "passphrase"); err != nil {
		t.Fatalf("run backup: %v", err)
	}
}

func TestRunBackupWithClientPartialFailureTolerated(t *testing.T) {
	setTestDB(t)

	client := &fakeClient{
		projects: []doppler.Project{{Name: "proj-a"}},
		configsByProject: map[string][]doppler.Config{
			"proj-a": {{Name: "dev"}, {Name: "prd"}},
		},
		secretsByKey: map[string]map[string]string{
			"proj-a/dev": {"KEY": "val"},
		},
		downloadSecretsErr: map[string]error{
			"proj-a/prd": errors.New("download failed"),
		},
	}

	if err := runBackupWithClient(client, "", "passphrase"); err != nil {
		t.Fatalf("expected partial failure to be tolerated, got error: %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	snaps, err := st.ListSnapshots("")
	if err != nil {
		t.Fatalf("list snapshots: %v", err)
	}
	if len(snaps) != 1 {
		t.Fatalf("expected 1 snapshot from the successful config, got %d", len(snaps))
	}
}

func TestRunBackupWithClientAllFailReturnsError(t *testing.T) {
	setTestDB(t)

	client := &fakeClient{
		projects: []doppler.Project{{Name: "proj-a"}},
		listConfigsErr: map[string]error{
			"proj-a": errors.New("list configs failed"),
		},
	}

	if err := runBackupWithClient(client, "", "passphrase"); err == nil {
		t.Fatalf("expected error when every backup fails")
	}
}

func TestRunRestoreWithClientLatestSnapshot(t *testing.T) {
	setTestDB(t)

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	key, err := crypto.DeriveKey("passphrase", salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	plaintext := []byte(`{"KEY":"val"}`)
	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce, ciphertext); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	st.Close()

	client := &fakeClient{}
	if err := runRestoreWithClient(client, "proj", "dev", "passphrase", 0); err != nil {
		t.Fatalf("run restore: %v", err)
	}

	if client.uploadedProject != "proj" || client.uploadedConfig != "dev" {
		t.Fatalf("unexpected upload target: project=%q config=%q", client.uploadedProject, client.uploadedConfig)
	}
	if string(client.uploadedContent) != string(plaintext) {
		t.Fatalf("expected uploaded content %q, got %q", plaintext, client.uploadedContent)
	}
	if _, err := os.Stat(client.uploadedPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file %q to be removed after restore, stat err: %v", client.uploadedPath, err)
	}
}

// TestRestoreCleansUpTempFileOnSignal verifies the SIGINT handler installed
// around restore's plaintext temp file: it re-execs this test binary as a
// child process that restores a snapshot via a client whose UploadSecrets
// deliberately stalls, sends SIGINT mid-upload, and asserts the temp file
// is gone once the child exits. This exercises the actual cleanup path
// (main.go's signal.Notify/os.Exit), which a plain unit test can't reach
// since it requires killing a real process.
func TestRestoreCleansUpTempFileOnSignal(t *testing.T) {
	if os.Getenv("DOPPLER_BACKUP_SIGTEST_CHILD") == "1" {
		signalTestChildMain()
		return
	}

	sigDBPath := filepath.Join(t.TempDir(), "sig.db")
	pathFile := filepath.Join(t.TempDir(), "tmp-path.txt")

	cmd := exec.Command(os.Args[0], "-test.run=^TestRestoreCleansUpTempFileOnSignal$")
	cmd.Env = append(os.Environ(),
		"DOPPLER_BACKUP_SIGTEST_CHILD=1",
		"DOPPLER_BACKUP_SIGTEST_DB="+sigDBPath,
		"DOPPLER_BACKUP_SIGTEST_PATHFILE="+pathFile,
	)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}

	var tempPath string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(pathFile)
		if err == nil && len(b) > 0 {
			tempPath = string(b)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if tempPath == "" {
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatalf("child never reported a temp file path")
	}
	if _, err := os.Stat(tempPath); err != nil {
		t.Fatalf("expected temp file to exist before signal: %v", err)
	}

	if err := cmd.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatalf("signal child: %v", err)
	}
	_ = cmd.Wait()

	if _, err := os.Stat(tempPath); !os.IsNotExist(err) {
		t.Fatalf("expected temp file %q to be removed after SIGINT, stat err: %v", tempPath, err)
	}
}

// signalTestChildMain seeds a snapshot and restores it via a client whose
// UploadSecrets reports the temp file path and stalls, giving the parent
// test a window to deliver SIGINT.
func signalTestChildMain() {
	dbPath = os.Getenv("DOPPLER_BACKUP_SIGTEST_DB")
	pathFile := os.Getenv("DOPPLER_BACKUP_SIGTEST_PATHFILE")

	st, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		log.Fatalf("ensure salt: %v", err)
	}
	key, err := crypto.DeriveKey("passphrase", salt)
	if err != nil {
		log.Fatalf("derive key: %v", err)
	}
	nonce, ciphertext, err := crypto.Encrypt(key, []byte(`{"KEY":"val"}`))
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce, ciphertext); err != nil {
		log.Fatalf("save snapshot: %v", err)
	}
	st.Close()

	client := &slowUploadClient{pathFile: pathFile}
	if err := runRestoreWithClient(client, "proj", "dev", "passphrase", 0); err != nil {
		log.Fatalf("restore: %v", err)
	}
}

// slowUploadClient reports the temp file path it was handed and then stalls,
// simulating an upload that's still in flight when a signal arrives.
type slowUploadClient struct {
	pathFile string
}

func (c *slowUploadClient) ListProjects() ([]doppler.Project, error) { return nil, nil }
func (c *slowUploadClient) ListConfigs(string) ([]doppler.Config, error) {
	return nil, nil
}
func (c *slowUploadClient) DownloadSecrets(string, string) (map[string]string, error) {
	return nil, nil
}
func (c *slowUploadClient) UploadSecrets(_, _, path string) error {
	if err := os.WriteFile(c.pathFile, []byte(path), 0o600); err != nil {
		return err
	}
	time.Sleep(3 * time.Second)
	return nil
}

func TestPlaintextTempDirPrefersTmpfs(t *testing.T) {
	dir := plaintextTempDir()
	if _, err := os.Stat("/dev/shm"); err == nil {
		if dir != "/dev/shm" {
			t.Fatalf("expected /dev/shm when available, got %q", dir)
		}
	}
}

func TestRunRestoreWithClientSpecificSnapshotID(t *testing.T) {
	setTestDB(t)

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	key, err := crypto.DeriveKey("passphrase", salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}

	firstPlaintext := []byte(`{"KEY":"first"}`)
	nonce1, ciphertext1, err := crypto.Encrypt(key, firstPlaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce1, ciphertext1); err != nil {
		t.Fatalf("save snapshot 1: %v", err)
	}
	firstSnap, err := st.LatestSnapshot("proj", "dev")
	if err != nil {
		t.Fatalf("latest snapshot: %v", err)
	}

	secondPlaintext := []byte(`{"KEY":"second"}`)
	nonce2, ciphertext2, err := crypto.Encrypt(key, secondPlaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce2, ciphertext2); err != nil {
		t.Fatalf("save snapshot 2: %v", err)
	}
	st.Close()

	client := &fakeClient{}
	if err := runRestoreWithClient(client, "proj", "dev", "passphrase", firstSnap.ID); err != nil {
		t.Fatalf("run restore: %v", err)
	}
	if string(client.uploadedContent) != string(firstPlaintext) {
		t.Fatalf("expected restore of first snapshot %q, got %q", firstPlaintext, client.uploadedContent)
	}
}

func TestRunRestoreWithClientNoSnapshotFound(t *testing.T) {
	setTestDB(t)

	client := &fakeClient{}
	if err := runRestoreWithClient(client, "proj", "dev", "passphrase", 0); err == nil {
		t.Fatalf("expected error when no snapshot exists")
	}
}

func TestRunRestoreWithClientWrongPassphraseFails(t *testing.T) {
	setTestDB(t)

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	key, err := crypto.DeriveKey("correct-passphrase", salt)
	if err != nil {
		t.Fatalf("derive key: %v", err)
	}
	nonce, ciphertext, err := crypto.Encrypt(key, []byte(`{"KEY":"val"}`))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce, ciphertext); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	st.Close()

	client := &fakeClient{}
	if err := runRestoreWithClient(client, "proj", "dev", "wrong-passphrase", 0); err == nil {
		t.Fatalf("expected error when restoring with the wrong passphrase")
	}
}

func TestRunRotateEndToEnd(t *testing.T) {
	path := setTestDB(t)

	st, err := store.Open(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		t.Fatalf("ensure salt: %v", err)
	}
	oldKey, err := crypto.DeriveKey("old-passphrase", salt)
	if err != nil {
		t.Fatalf("derive old key: %v", err)
	}
	nonce, ciphertext, err := crypto.Encrypt(oldKey, []byte(`{"KEY":"val"}`))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := st.SaveSnapshot("proj", "dev", nonce, ciphertext); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	st.Close()

	if err := runRotate("old-passphrase", "new-passphrase"); err != nil {
		t.Fatalf("run rotate: %v", err)
	}

	matches, err := filepath.Glob(path + ".bak-*")
	if err != nil {
		t.Fatalf("glob backup files: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected exactly 1 backup file, got %v", matches)
	}

	client := &fakeClient{}
	if err := runRestoreWithClient(client, "proj", "dev", "old-passphrase", 0); err == nil {
		t.Fatalf("expected old passphrase to fail after rotation")
	}
	if err := runRestoreWithClient(client, "proj", "dev", "new-passphrase", 0); err != nil {
		t.Fatalf("expected new passphrase to succeed after rotation: %v", err)
	}
}

func TestCopyFileCreatesRestrictedBackup(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	if err := os.WriteFile(src, []byte("db-contents"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	dst, err := copyFile(src)
	if err != nil {
		t.Fatalf("copy file: %v", err)
	}

	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat backup file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("expected backup file permissions 0o600, got %o", perm)
	}
	content, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read backup file: %v", err)
	}
	if string(content) != "db-contents" {
		t.Fatalf("expected backup content %q, got %q", "db-contents", content)
	}
}

func TestCopyFileFailsOnExistingDestination(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	if err := os.WriteFile(src, []byte("db-contents"), 0o600); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	first, err := copyFile(src)
	if err != nil {
		t.Fatalf("copy file: %v", err)
	}
	// Pre-create the exact destination copyFile will pick next, rather than
	// relying on same-second timing, to reliably exercise the O_EXCL path.
	if err := os.WriteFile(first, []byte("already-here"), 0o600); err != nil {
		t.Fatalf("recreate backup file: %v", err)
	}

	if _, err := copyFile(src); err == nil {
		t.Fatalf("expected error when backup destination already exists")
	}
}

func TestRequiredFlagsEnforced(t *testing.T) {
	// --passphrase is intentionally not required on any command: omitting
	// it falls back to an interactive prompt, or defaultPassphrase when
	// stdin isn't a terminal (see TestResolvePassphrase).
	restoreCmd := newRestoreCmd()
	restoreCmd.SetArgs([]string{"--project", "p"})
	restoreCmd.SilenceUsage = true
	restoreCmd.SilenceErrors = true
	if err := restoreCmd.Execute(); err == nil {
		t.Fatalf("expected error when --config is missing from restore")
	}
}

func TestResolvePassphrase(t *testing.T) {
	pass, err := resolvePassphrase("explicit", "Passphrase")
	if err != nil || pass != "explicit" {
		t.Fatalf("expected explicit flag value to win, got %q, %v", pass, err)
	}

	// go test's stdin isn't a terminal, so an empty flag falls back to the
	// default passphrase without blocking on a prompt.
	pass, err = resolvePassphrase("", "Passphrase")
	if err != nil || pass != defaultPassphrase {
		t.Fatalf("expected default passphrase for non-interactive stdin, got %q, %v", pass, err)
	}
}

func TestResolveNewPassphrase(t *testing.T) {
	pass, err := resolveNewPassphrase("explicit")
	if err != nil || pass != "explicit" {
		t.Fatalf("expected explicit flag value to win, got %q, %v", pass, err)
	}

	pass, err = resolveNewPassphrase("")
	if err != nil || pass != defaultPassphrase {
		t.Fatalf("expected default passphrase for non-interactive stdin, got %q, %v", pass, err)
	}
}

func TestRunListEmptyAndPopulated(t *testing.T) {
	setTestDB(t)

	if err := runList(""); err != nil {
		t.Fatalf("run list (empty): %v", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := st.SaveSnapshot("proj-a", "dev", []byte("n"), []byte("c")); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}
	st.Close()

	if err := runList(""); err != nil {
		t.Fatalf("run list (populated): %v", err)
	}
	if err := runList("proj-a"); err != nil {
		t.Fatalf("run list (filtered): %v", err)
	}
	if err := runList("no-such-project"); err != nil {
		t.Fatalf("run list (filtered, no matches): %v", err)
	}
}
