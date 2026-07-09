# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/johndotmcgann/doppler-backup/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/johndotmcgann/doppler-backup/releases/tag/v0.1.0
