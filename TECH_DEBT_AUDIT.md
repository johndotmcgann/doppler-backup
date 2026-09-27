# Tech Debt Audit — doppler-backup

Generated: 2026-09-27

## Executive summary

- This is a small (~1,150 source / ~1,490 test lines), single-purpose Go CLI that has already
  been through multiple audit-and-fix cycles (CHANGELOG documents F01–F22 resolved between
  v0.3.0 and v1.0.0: chmod races, passphrase-resolution duplication, scrypt constant naming,
  a flaky signal test, etc.). It shows.
- No god files, no circular deps, no dead code, no `any`-style type escape hatches (this is
  Go — there's no equivalent to flag), gofmt clean, `go vet` clean, `govulncheck` clean at the
  code level.
- The most material gap is process, not code: a GitHub PR literally named `vuls-check`
  (merged as 4a9a2db) landed a gofmt CI check and a Go-version dedup, but **never added the
  vulnerability check its name promised** — `govulncheck` is installed in the dev container
  (Dockerfile.dev-go) but never runs in CI. See F01.
- Two concrete reliability gaps worth fixing: no SQLite busy-timeout, so cron overlap or a
  `rotate` racing a `backup` fails immediately instead of waiting (F04); and `restore`'s
  tmpfs-preferred temp file has no fallback if `/dev/shm` exists but isn't writable (F05).
- Two small but real documentation-drift items: `CLAUDE.md` misattributes `godocs/` generation
  to `build.sh` when it's actually `godocs.sh` (F02), and `build.sh`'s own header comment
  still claims it "always... installs the executable to $HOME/Executables," a step removed in
  commit b104397 (F03).
- `govulncheck` reports 10 advisories in the stdlib/x-crypto versions pinned in `go.mod`
  (go1.26.5, x/crypto v0.54.0); none are reachable from this code today, but closing them is a
  one-line bump (F07).
- Given the codebase's size and its prior audit history, this report has 8 findings, not 30+.
  Padding a clean, small, already-hardened codebase to hit a round number would be noise —
  see "Things that look bad but are actually fine" for the calls deliberately *not* made.

## Architectural mental model

`doppler-backup` is a cobra-based CLI with four subcommands (`backup`, `restore`, `list`,
`rotate`) wired in `cmd/doppler-backup/main.go`, delegating to three independent `internal/`
packages with a strict one-way dependency: `main` imports `doppler`, `crypto`, and `store`;
none of the three import each other. `doppler` shells out to the `doppler` CLI binary (never
calls Doppler's API directly) behind a swappable `runFunc`, which is how tests avoid needing a
real `doppler` install. `crypto` is a pure, stateless AES-256-GCM/scrypt library with no
knowledge of Doppler or SQLite. `store` is a thin SQLite persistence layer (`modernc.org/sqlite`,
no cgo) that only ever touches ciphertext — it has no `crypto` import, and the identical
`store.KDFParams`/`crypto.Params` struct shapes are bridged by a same-underlying-type
conversion at the call site rather than a shared import, which is a deliberate decoupling, not
an accident (confirmed by the package doc comments in both files).

The design is unusually explicit about its own security trade-offs for a project this size —
README and CLAUDE.md both spell out *why* particular corners were cut (e.g., no
"restore-everything" mode, no environment-variable passphrase fallback, decrypt-only
passphrases skip the length floor) rather than leaving them to be reverse-engineered. This
matches the CHANGELOG history: several past findings were security hardening
(chmod race window, default-passphrase removal, scrypt strengthening) rather than the usual
mix of "add feature, patch bug." The codebase reads as maintained by someone who treats an
audit as a live process, not a one-off — which shifts what's worth flagging here away from
"the obvious stuff" (already fixed) and toward narrower gaps: a CI check that was promised by
name but not delivered, two edge-case reliability gaps, and small doc/comment drift from two
recent refactors.

## Findings

| ID | Category | File:Line | Severity | Effort | Description | Recommendation |
|----|----------|-----------|----------|--------|--------------|-----------------|
| F01 | Dependency & config debt | `.github/workflows/ci.yml:1-19` | Medium | S | CI runs `go vet`, `gofmt -l`, and `go test`, but no vulnerability scan. PR #1 was named `vuls-check` (merge commit 4a9a2db) and its own description says "Dedupe Go version pin, add gofmt CI check, fix CHANGELOG links" — no vuln-check step ever landed. `govulncheck` is already installed in `Dockerfile.dev-go:22-23` for manual use but isn't wired into automation. | Add a `govulncheck ./...` step to `ci.yml` (e.g. via `golang.org/x/vuln/cmd/govulncheck@latest` or the `golang/govulncheck-action`). |
| F02 | Documentation drift | `CLAUDE.md:78` | Low | S | "`testresults/` and `godocs/` are generated artifacts (from `build.sh`)" — but `godocs/` is produced by the separate `godocs.sh` script, not `build.sh`; `build.sh:86` itself says "For local godoc HTML docs, run ./godocs.sh separately," and `CLAUDE.md:30-32` two paragraphs earlier correctly makes this distinction. The Notes section contradicts the file's own Architecture section. | Reword to "`testresults/` (from `build.sh`) and `godocs/` (from `godocs.sh`) are generated artifacts." |
| F03 | Documentation drift | `build.sh:3-4` | Low | S | Header comment: "Production build script for doppler-backup. Always builds and installs the executable to $HOME/Executables." The install-to-`$HOME/Executables` step was removed in commit b104397 ("Remove local-install step from build.sh"); the script now only builds to `bin/`. | Update the header comment to match current behavior (build + vet + test to `bin/`, no install step). |
| F04 | Performance & resource hygiene | `internal/store/store.go:66` | Medium | S | `sql.Open("sqlite", path)` sets no `busy_timeout` PRAGMA. CLAUDE.md documents this tool as "expected to be invoked by cron or similar," and SQLite's default busy behavior is to fail immediately with `SQLITE_BUSY` rather than wait — so an overlapping cron run, or `rotate` started while a `backup` is still writing, surfaces as an immediate "database is locked" error instead of a short, silent wait. | Add a busy timeout via the DSN, e.g. `sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")`, and add a test that opens two `*Store` on the same file concurrently. |
| F05 | Error handling & reliability | `cmd/doppler-backup/main.go:321-326`, `357-360` | Medium | S | `plaintextTempDir()` returns `/dev/shm` whenever it exists as a directory, with no check that it's actually writable or has free space. If `/dev/shm` exists but is read-only, full, or `noexec`-mounted-with-restrictive-perms (plausible in some containers/CI sandboxes), `os.CreateTemp` at `main.go:357` fails and `restore` aborts outright — even though falling back to the OS default temp dir (the documented fallback behavior) would succeed. | On `os.CreateTemp` failure against a non-empty `plaintextTempDir()`, retry once with `""` (OS default) before giving up. |
| F06 | Test debt | `cmd/doppler-backup/main_test.go:43-44` (field), `84-92` (method) | Low | S | `fakeClient` has a `versionErr` field wired into `Version()`, but no test ever sets it. Every `TooOldVersionFailsFast` test simulates an *old but successfully returned* version string; none simulate `client.Version()` itself failing (e.g., the real `doppler` binary missing from PATH), so `checkDopplerVersion`'s `if err != nil { return err }` branch at `main.go:79-82` is untested for that path. | Add `TestRunBackupWithClientVersionCheckErrorFailsFast` (and the restore equivalent) using `&fakeClient{versionErr: errors.New(...)}`. |
| F07 | Dependency & config debt | `go.mod:3,7` | Low | S | `govulncheck ./...` (module scan) reports 10 advisories against the pinned toolchain/dep versions: `go1.26.5` (fixed in `go1.26.6`, 7 stdlib advisories) and `golang.org/x/crypto@v0.54.0` (fixed in v0.55.0/v0.56.0, 3 advisories in the unused `x/crypto/ssh` subpackage plus the unmaintained `x/crypto/openpgp`). None are reachable from this project's actual call paths (symbol-level scan: 0 vulnerabilities), but they're free to close. | Bump the `go` directive to `1.26.6` and run `go get -u golang.org/x/crypto@latest`. |
| F08 | Consistency rot | `godocs.sh:90-91` | Low | S | `INTERNAL_PKGS=$(go list ./... | grep "/internal/" || true)` defensively handles grep's exit-1-on-no-match under `set -e`, but the equivalent line just above it, `ROOT_PKGS=$(go list ./... | grep -v "/internal/")`, doesn't have the same guard. Currently harmless (there's always at least one non-internal package, `cmd/doppler-backup`), but the two lines use an inconsistent defensive pattern for the same failure mode. | Add `|| true` to the `ROOT_PKGS` line for consistency, or note in a comment why it's safe to omit. |

## Top 5 — if you fix nothing else, fix these

1. **F01 — Wire `govulncheck` into CI.** The gap between what PR #1's branch name promised
   (`vuls-check`) and what it shipped (gofmt + version dedup) is the kind of thing that's easy
   to believe is covered until an actual CVE lands in a dependency. Add to `ci.yml`:
   ```yaml
   - name: Vulnerability check
     run: go run golang.org/x/vuln/cmd/govulncheck@latest ./...
   ```
2. **F04 — Add a busy timeout to the SQLite DSN.** One-line change with an outsized payoff for
   a tool whose primary invocation path is unattended cron:
   ```go
   db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)")
   ```
3. **F05 — Fall back off `/dev/shm` on `CreateTemp` failure**, not just on its absence:
   ```go
   tmp, err := os.CreateTemp(plaintextTempDir(), "doppler-backup-*.json")
   if err != nil && plaintextTempDir() != "" {
       tmp, err = os.CreateTemp("", "doppler-backup-*.json")
   }
   ```
4. **F02 + F03 — Fix the two doc/comment drift spots** while they're fresh (both are one-line
   edits, both were introduced by the same recent refactor wave: b104397 for build.sh, and
   whatever commit split `godocs.sh` out for CLAUDE.md's stale Notes section).
5. **F07 — Bump `go.mod`'s `go` directive and `x/crypto`.** Not urgent (nothing reachable), but
   cheap enough that leaving it is just letting `govulncheck ./...`'s output stay noisy for no
   reason.

## Quick wins

- [ ] F01: Add a `govulncheck ./...` step to `.github/workflows/ci.yml`.
- [ ] F04: Add `?_pragma=busy_timeout(5000)` to the SQLite DSN in `store.Open`.
- [ ] F05: Retry `os.CreateTemp` against the OS default temp dir if `/dev/shm` exists but fails.

## Things that look bad but are actually fine

- **`os.Exit(1)` inside a goroutine, `main.go:373`.** Calling `os.Exit` from a spawned
  goroutine usually reads as a bug (it skips every other deferred cleanup in the program). Here
  it's deliberate: on SIGINT/SIGTERM mid-restore, the only cleanup that matters is deleting the
  plaintext temp file, which happens on the line immediately before; an orderly shutdown would
  add complexity for a codepath that's about to terminate anyway. Covered by
  `TestRestoreCleansUpTempFileOnSignal`.
- **`copyFile`'s `O_EXCL` failure on same-second collisions, `main.go:515`.** Two `rotate` runs
  within the same wall-clock second will collide on the `.bak-<unix-timestamp>` name and the
  second one fails loudly. This looks like a race bug but is the intended behavior — the
  alternative (silently overwriting a just-made safety backup) is worse than a rare, loud
  failure. `TestCopyFileFailsOnExistingDestination` exercises this deliberately.
- **`RotateKey` loads every snapshot into memory (`store.go:219-234`).** No pagination, no
  streaming. For the tool's actual scale (one operator's Doppler projects/configs, backed up on
  a cron schedule) this is dozens to low-thousands of rows, not millions; a transaction that
  holds all of them in memory is simpler and still fast at that scale.
- **`dopplerClient` interface lives in `main`, not in `internal/doppler`.** Defining a narrow
  consumer-side interface at the point of use rather than exporting one from the producer
  package looks backwards at first glance but is idiomatic Go and is exactly what
  `CLAUDE.md:61-63` documents as the intended test seam.
- **`tmp.Chmod(0o600)` in `main.go:382` looks redundant** — `os.CreateTemp` already creates
  files at `0600`. It's consistent with this codebase's demonstrated pattern of explicit,
  defense-in-depth permission-setting (see `store.Open`'s near-identical chmod-after-create,
  added deliberately in commit 232ea0b to close a chmod-race window). Leaving it costs nothing
  and matches the project's established style for security-sensitive file creation.
- **`--passphrase` on the command line is visible via `ps`/argv on multi-user systems.** This
  looks like a gap, but it's a known, already-documented trade-off: the interactive prompt
  (which doesn't leak via argv) is the default path, the flag exists specifically for
  unattended/cron use, and an environment-variable alternative was already considered and
  explicitly rejected (README: "there is no default and no environment-variable fallback";
  see commit 3ec8727, which removed a *different* env-adjacent shortcut — a hardcoded default
  passphrase — for similar exposure reasons). Re-litigating this without new information would
  be second-guessing a documented decision, not finding new debt.
- **`crypto.Params` and `store.KDFParams` are structurally identical types requiring an
  explicit conversion at every call site** (`crypto.Params(params)`, `store.KDFParams(...)`).
  This first reads as accidental duplication ("multiple ways of representing the same data"),
  but both packages' doc comments make the decoupling explicit: `store` deliberately has "no
  opinion" on what N/R/P mean cryptographically. Collapsing them into a shared type would
  create the exact cross-package coupling the design avoids.
- **`main.go` is 525 lines**, just over the audit's nominal 500-line god-file threshold. It
  doesn't exhibit god-file symptoms, though: it's four cleanly separated command
  constructors/handlers plus a shared passphrase-resolution helper, no mixed responsibilities,
  no deep nesting. Splitting it (e.g., one file per subcommand) would trade a single easy-to-
  scan file for cross-file navigation with no reduction in actual coupling.

## Open questions for the maintainer

- F01's fix is a one-line CI addition, but is there an existing reason `govulncheck` was left
  as dev-container-only rather than wired into CI (e.g. false-positive noise from
  `modernc.org/sqlite`'s C-derived dependency tree)? If so, worth a comment in `ci.yml`
  explaining the omission rather than leaving it silent.
- `Dockerfile.dev-go` currently has an uncommitted local diff (per `git status`) adding
  `govulncheck`/`godoc`/`golangci-lint` installs — is that in-flight work related to closing
  F01, or unrelated droplet-tooling setup? Worth confirming before someone else picks up F01
  and duplicates the CI-wiring half of it.
- Is the `.bak-<unix-timestamp>` collision behavior in `copyFile` (see "looks bad but fine")
  something you'd rather see softened (e.g. append a monotonic counter or PID on collision) now
  that it's had time to be a real annoyance, or is the current loud-failure-on-collision
  behavior still the preferred trade-off?
