# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`doppler-backup` is a CLI that snapshots Doppler secrets (per project/config) into a local
SQLite database, encrypted at rest, and can restore snapshots back into Doppler. It shells
out to the `doppler` CLI rather than calling Doppler's API directly.

## Commands

```sh
make build          # build ./bin/doppler-backup
make install         # go install into $GOPATH/bin
make test            # go test ./...
make vet             # go vet ./...
make fmt             # gofmt -l -w .
```

Run a single test:

```sh
go test ./internal/crypto/... -run TestDeriveKey -v
```

`build.sh` is the production build script (version bump via `--major`/`--minor`/`--patch`,
runs vet + tests, builds with `-ldflags -X main.Version=<tag>` to `bin/doppler-backup`).
It's not needed for routine development — `make build`/`make test` are
the day-to-day commands. `godocs.sh` is a separate, optional script that regenerates local
`godocs/` HTML via `godoc`; it's not part of the production build since pkg.go.dev indexes
the public module automatically.

## Architecture

Three packages under `internal/`, each with a single responsibility, wired together in
`cmd/doppler-backup/main.go`:

- **`internal/doppler`**: wraps the `doppler` CLI via `exec.Command`. `Client` has a
  swappable `runFunc` field so tests can fake CLI output without shelling out. Handles
  pagination (100/page) for `ListProjects`/`ListConfigs`, and strips Doppler's computed
  `DOPPLER_PROJECT`/`DOPPLER_CONFIG`/`DOPPLER_ENVIRONMENT` keys from downloaded secrets
  since they describe the target config rather than being real secret data. `MinVersion`
  pins the oldest doppler CLI version this tool is verified against; `CheckMinVersion` is
  enforced at the top of `backup`/`restore` in `main.go` (via `dopplerClient.Version()`) so
  a too-old CLI fails fast instead of producing a confusing JSON-parse error later.
- **`internal/crypto`**: passphrase-based encryption only — never touches Doppler or SQLite.
  A random salt (`GenerateSalt`) is generated once per database and stored in the `meta`
  table; `DeriveKey` runs scrypt(passphrase, salt) to get a 32-byte AES key each run.
  `Encrypt`/`Decrypt` do AES-256-GCM with a fresh random nonce per snapshot. `Decrypt`
  deliberately collapses "wrong passphrase" and "corrupted ciphertext" into one error
  message (`incorrect passphrase or corrupted snapshot`) — GCM's auth tag makes those the
  only two possibilities, so there's nothing more specific to say.
- **`internal/store`**: SQLite persistence (`modernc.org/sqlite`, pure Go, no cgo). Only
  ever sees ciphertext — encryption/decryption is the caller's job. Two tables: `meta`
  (single-row KDF salt) and `snapshots` (one row per project/config/timestamp). Opens the
  DB file at `0600`. `RotateKey` re-encrypts every snapshot and swaps the salt inside one
  transaction, so a rotation either fully succeeds or leaves the database untouched.

`cmd/doppler-backup/main.go` wires these together per subcommand (`backup`, `restore`,
`list`, `rotate`) via cobra. The `dopplerClient` interface there (not in the `doppler`
package) is the seam `main_test.go` uses to inject a fake Doppler client — look there first
when testing CLI behavior without a real `doppler` binary.

Key behavioral details worth knowing before changing command logic:

- `backup` continues past a failed project/config (logs and skips) and only returns an
  error if *every* attempt failed — a locked/inaccessible config shouldn't abort the whole
  run.
- `restore` requires explicit `--project`/`--config`; there is intentionally no
  "restore everything" mode. Writes decrypted plaintext to a `0600` temp file, uploads via
  `doppler secrets upload`, then removes the temp file.
- `rotate` copies the whole DB file to `<db>.bak-<unix timestamp>` before touching anything,
  as a safety net independent of the in-transaction rotation.

## Notes

- `testresults/` (from `build.sh`) and `godocs/` (from `godocs.sh`) are generated
  artifacts, not source — don't hand-edit them.
- No built-in scheduling; `doppler-backup backup` is expected to be invoked by cron or
  similar.

## Release workflow

Ship every feature or fix in this order and stop at the first failing step:

1. Implement.
2. Add or update tests.
3. Run the tests (`make test`) in this project's workspace container on the droplet. One build or test run at a time: the droplet is 1 vCPU / 2 GB, so never start a second build while one is running.
4. Update `CHANGELOG.md`.
5. Commit locally (multiple `-m` flags, no heredocs).
6. Tag `vX.Y.Z` (semver) after checking `git tag --sort=-v:refname | head -3`. Never move or reuse a tag, and never create throwaway/test tags on this repo; verify build-script changes with a dry run instead.
7. Deliver: on the client, run `~/bin/fetch-doppler-backup.sh --build` to build in the workspace container and copy the binary back. Nothing is installed on the droplet (dev-only).
8. Report "ready" with the commit and tag. Do not `git push` (commits or tags) unless I explicitly ask.
