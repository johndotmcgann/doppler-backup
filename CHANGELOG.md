# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Bumped the Go directive to 1.26.6 and `golang.org/x/crypto` to v0.56.0,
  clearing all `govulncheck` advisories except the unmaintained
  `x/crypto/openpgp` package, which is not imported and has no fixed
  version. `DeriveKey` output is unchanged, so existing databases still
  decrypt.

## [1.0.0] - 2026-08-03

First stable release, coinciding with the repository going public.

### Added

- GitHub Actions CI workflow (runs `go vet` and `go test ./...` on push/PR)
  and a release workflow that builds and attaches binaries to GitHub
  Releases on tag push.
- README documentation on prebuilt binary downloads, building from source,
  and who this application is suitable for.

### Changed

- Split godoc HTML generation out of `build.sh` into a separate
  `godocs.sh` script; it's no longer part of the production build since
  pkg.go.dev indexes the public module automatically.
- Bumped `actions/checkout` and `actions/setup-go` to v7 in CI workflows.

## [0.10.0] - 2026-07-12

### Fixed

- The backup SQLite database could briefly be created under the process
  umask (e.g. world-readable) before `store.Open` locked it down to
  `0600`. The file is now created at `0600` from the start, closing that
  window.

### Changed

- Consolidated the three passphrase-resolution functions
  (`resolvePassphrase`, `resolveEncryptPassphrase`, `resolveNewPassphrase`)
  into a single shared helper parameterized by a validation function and an
  optional confirmation prompt.
- `dbPath` is no longer a package-level global; it's threaded explicitly
  through the `run*` functions and command constructors, removing a latent
  hazard for future parallel tests.
- Scrypt's legacy "interactive" defaults (`32768`/`8`/`1`), previously
  duplicated across two SQL DDL strings and two test files, are now backed
  by a single named constant.
- De-flaked `TestRestoreCleansUpTempFileOnSignal`: the child process now
  reports its temp file path over a pipe the instant it exists, instead of
  the parent polling for up to 5 seconds.

## [0.9.0] - 2026-07-11

### Added

- Minimum Doppler CLI version check (3.76.0): `backup` and `restore` now
  fail fast with a clear error if the installed `doppler` binary is older
  than this or its `--version` output can't be parsed, instead of hitting a
  confusing JSON-parse error deeper in the run.

## [0.8.0] - 2026-07-11

### Removed

- Default-passphrase fallback (`doppler_backup`): omitting `--passphrase`
  (or `--old-passphrase`/`--new-passphrase` for `rotate`) now prompts
  interactively, or errors when run non-interactively (e.g. cron), instead
  of silently encrypting under a guessable constant.

### Added

- Minimum passphrase length (12 characters) enforced for passphrases that
  encrypt new data (`backup`, `rotate --new-passphrase`). Passphrases used
  only to decrypt existing data (`restore`, `rotate --old-passphrase`)
  remain unrestricted so databases created before this change stay
  restorable.

## [0.7.0] - 2026-07-10

### Changed

- `crypto.DefaultParams()` scrypt work factor raised from `N = 1<<15`
  (scrypt's 2009 "interactive" default) to `N = 1<<17`. KDF parameters
  (`N`/`R`/`P`) are now persisted alongside the salt in the `meta` table
  instead of hardcoded, so each database re-derives its key with whatever
  parameters it was actually created under. Pre-existing databases are
  backfilled to the old constants (`32768/8/1`) on open, so already-stored
  snapshots keep decrypting without requiring `rotate`; only new databases
  (or ones that go through `rotate`) get the stronger work factor.

## [0.6.0] - 2026-07-10

### Changed

- `restore`'s decrypted-secrets temp file now prefers `/dev/shm` (tmpfs)
  over disk when available, and a `SIGINT`/`SIGTERM` handler removes it
  if the process is interrupted mid-restore. `SIGKILL`/hard crashes can
  still leave it behind — documented in the README.
- Deduplicated salt-reading in `internal/store` (`readSalt()` shared by
  `EnsureSalt`/`CurrentSalt`) and store-open-plus-key-derivation in
  `cmd/doppler-backup` (`openStoreAndKey()` shared by `backup`/`restore`).
- Bumped `go` directive to 1.26.5 and `golang.org/x/crypto` to v0.54.0
  (pulling `golang.org/x/term` to v0.45.0 and `golang.org/x/sys` to
  v0.47.0), closing two disclosed-but-unreached Go stdlib CVEs.

### Removed

- Vestigial `/doppler-backup` rule from `.gitignore`; the Makefile has
  always built to `bin/doppler-backup`, already covered by `/bin/`.

## [0.5.0] - 2026-07-10

### Added

- Interactive passphrase prompt: `--passphrase` (and
  `--old-passphrase`/`--new-passphrase` for `rotate`) are no longer
  required flags. When omitted and stdin is a terminal, the CLI prompts
  for the passphrase without echoing input; `rotate`'s new passphrase is
  confirmed by prompting twice. A blank prompt entry, or a
  non-interactive stdin (e.g. cron) without the flag, falls back to a
  fixed default passphrase (`doppler_backup`) so existing scripted usage
  keeps working unattended.

### Changed

- `make build`/`make install` now stamp a real version via
  `-ldflags -X main.Version=...` (derived from `git describe`), matching
  what `build.sh` already did. Previously the documented `make build`
  path always reported `version dev`.
- `build.sh` is now committed to the repository instead of being
  gitignored, so version injection, vet/test gating, and doc generation
  for releases are reviewable and reproducible. The `$HOME/Executables`
  copy step is now opt-in via `INSTALL_LOCAL=1`.

### Fixed

- `build.sh`'s test-results capture (`testresults/*.json`) no longer
  produces an empty file on a failing test run. It now tees `go test
  -json` output through `pipefail` (previously a plain `sh` redirect
  couldn't trip `set -e` on failure) and only creates the results file
  after `go vet` passes.

## [0.4.0] - 2026-07-09

### Changed

- `list` command's timestamp column header now reads `TAKEN AT (UTC)` to
  make clear the recorded snapshot time is in UTC.

## [0.3.0] - 2026-07-09

### Added

- Test coverage across all packages: `internal/crypto` (encrypt/decrypt
  round-trips, key derivation, tamper/wrong-key failures), `internal/store`
  (salt persistence, snapshot CRUD, file permissions), `internal/doppler`,
  and the `backup`/`restore`/`rotate` CLI orchestration logic. Small,
  behavior-preserving dependency-injection seams were added to
  `doppler.Client` and `cmd/doppler-backup` so these can be tested with
  fakes instead of a real `doppler` binary.

## [0.2.0] - 2026-07-09

### Added

- `rotate` command to re-encrypt every stored snapshot under a new
  passphrase, invalidating the old one. Rotation runs inside a single
  transaction (all-or-nothing) and copies the database to a timestamped
  `.bak` file before making changes as a safety net.

## [0.1.0] - 2026-07-08

### Added

- Initial release: `backup`, `restore`, and `list` commands for
  snapshotting and restoring Doppler secrets to/from a local
  AES-256-GCM-encrypted SQLite database.
- Version injection for production builds via `build.sh`.
- README with usage instructions and MIT license.

[1.0.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.10.0...v1.0.0
[0.10.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/johndotmcgann/doppler-backup/releases/tag/v0.1.0
