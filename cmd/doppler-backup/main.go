package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mcgannj/doppler-backup/internal/crypto"
	"github.com/mcgannj/doppler-backup/internal/doppler"
	"github.com/mcgannj/doppler-backup/internal/store"
)

// Version is set at build time via -ldflags "-X main.Version=<git tag>".
var Version = "dev"

var dbPath string

func main() {
	root := &cobra.Command{
		Use:           "doppler-backup",
		Short:         "Emergency backup/restore for Doppler secrets, snapshotted to an encrypted local SQLite database",
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&dbPath, "db", "./doppler-backup.db", "path to the SQLite backup database")

	root.AddCommand(newBackupCmd(), newRestoreCmd(), newListCmd())

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func newBackupCmd() *cobra.Command {
	var project, passphrase string
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "Snapshot secrets for all projects (or one, with --project) into the backup database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBackup(project, passphrase)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "limit backup to a single project (default: all projects)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to encrypt secrets at rest (required)")
	cmd.MarkFlagRequired("passphrase")
	return cmd
}

func runBackup(project, passphrase string) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return err
	}

	client := doppler.NewClient()

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

func backupOne(st *store.Store, client *doppler.Client, key []byte, project, config string) error {
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
			return runRestore(project, config, passphrase, snapshotID)
		},
	}
	cmd.Flags().StringVar(&project, "project", "", "project to restore into (required)")
	cmd.Flags().StringVar(&config, "config", "", "config to restore into (required)")
	cmd.Flags().StringVar(&passphrase, "passphrase", "", "passphrase used to decrypt the snapshot (required)")
	cmd.Flags().Int64Var(&snapshotID, "snapshot", 0, "specific snapshot id to restore (default: latest for project/config)")
	cmd.MarkFlagRequired("project")
	cmd.MarkFlagRequired("config")
	cmd.MarkFlagRequired("passphrase")
	return cmd
}

func runRestore(project, config, passphrase string, snapshotID int64) error {
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	salt, err := st.EnsureSalt(crypto.GenerateSalt)
	if err != nil {
		return err
	}
	key, err := crypto.DeriveKey(passphrase, salt)
	if err != nil {
		return err
	}

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

	tmp, err := os.CreateTemp("", "doppler-backup-*.json")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmp.Name())
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

	client := doppler.NewClient()
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
	fmt.Printf("%-6s %-30s %-15s %s\n", "ID", "PROJECT", "CONFIG", "TAKEN AT")
	for _, s := range snaps {
		fmt.Printf("%-6d %-30s %-15s %s\n", s.ID, s.Project, s.Config, s.TakenAt.Format("2006-01-02 15:04:05"))
	}
	return nil
}
