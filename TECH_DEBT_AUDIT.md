# Tech Debt Audit — doppler-backup

Generated: 2026-07-10 (as `artifacts/TECH_DEBT_AUDIT_2026_07_10.md`)
Updated: 2026-07-11 — see prior audit's "Resolved 2026-07-11" / "Resolved
this session" sections (F01–F12 fixed, F10 added and fixed, F06 moot).
Updated: 2026-07-12 (this run) — re-audited against current `main`
(`dc05b69`). F13–F18 from the prior audit re-verified below; four new
findings (**F19–F22**) found this session. The correction below applies to
last session's initial attempt at this run before the prior audit was
located.

**Correction:** an earlier pass of this session's audit (before the prior
`artifacts/TECH_DEBT_AUDIT_2026_07_10.md` was located) flagged a "dangling
`TECH_DEBT_AUDIT.md` reference" in `main_test.go:584-586` as a documentation
drift finding. That's wrong — the file exists at
`artifacts/TECH_DEBT_AUDIT_2026_07_10.md`, and the F04/F06 IDs it cites
resolve correctly against that document. Retracted; not listed below.

## Executive summary

- The codebase remains small (2,587 LOC / 8 files), gofmt-clean, `go
  vet`/`staticcheck`-clean, no CVEs reachable in code actually called
  (`govulncheck`), and well-tested (67–95% coverage per package). Still not
  a neglected codebase — the prior audit's Top 5 are all fixed, and this
  pass mostly confirms that rather than finding new rot.
- **F19** (fixed this session): the encrypted backup SQLite file was
  briefly world-readable (confirmed by reproduction) before `store.Open`
  chmoded it to `0600`. Was the most concrete actionable finding in either
  audit round.
- **F20** (fixed this session): `resolvePassphrase` /
  `resolveEncryptPassphrase` / `resolveNewPassphrase` (added/extended by
  the F04 follow-up work in `962f774`/`3ec8727`, after the prior audit)
  duplicated the same terminal-check/prompt/blank-check shape three times.
  Collapsed into a shared `resolveWithPrompt` helper.
- Carried forward, still open, unchanged since 2026-07-10: **F13**
  (`dbPath` global mutated directly by tests), **F14** (`newGCM` rebuilt
  per call, immaterial at this scale), **F15** (unstructured stderr
  logging), **F16** (README/go.mod Go-version pin, still in sync — no
  drift), **F17** (`main()` itself untested, as expected).
- **F18** (stale generated artifacts) has improved: `testresults/*.json` is
  no longer empty (44–58KB per run, 5 runs on disk) and `godocs/` is
  current as of the latest `build.sh` run — the prior concern was about
  emptiness/staleness, both now resolved as a side effect of F03's fix.
  Downgraded to no-action.
- New this session: **F21** (scrypt legacy-default magic numbers duplicated
  across two DDL strings) and **F22** (one test is inherently more
  flake-prone than the rest of the suite, noted for future triage context).

## Architectural mental model

Unchanged from the 2026-07-10 audit: `doppler-backup` is a single Cobra
binary with three single-responsibility packages under `internal/`
(`doppler` shells out to the CLI, `crypto` is pure passphrase→key→AES-GCM
logic, `store` is a SQLite layer that only ever sees ciphertext), composed
per-subcommand in `cmd/doppler-backup/main.go` via a locally-defined
`dopplerClient` seam interface for testing. This still matches
CLAUDE.md/README exactly; no architecture-vs-docs drift found in either
audit round.

## Findings

| ID | Status | Category | File:Line | Severity | Effort | Description | Recommendation |
|----|--------|----------|-----------|----------|--------|-------------|-----------------|
| F01–F12 | ✅ Fixed (2026-07-10/11 session) | — | — | — | — | See `artifacts/TECH_DEBT_AUDIT_2026_07_10.md` for full detail (build.sh committed, Makefile version injection, testresults capture, passphrase prompting, temp-file signal cleanup, helper extraction, stale gitignore line, scrypt strengthening, toolchain/dependency bumps). | — |
| F13 | Open (carried forward, unchanged) | Architectural decay | cmd/doppler-backup/main.go:25 | Low-Medium | S-M | `dbPath` is a package-level mutable global read by every `run*` function; `main_test.go:25-32` mutates it directly via a save/restore helper. Still safe only because no test calls `t.Parallel()`. | Thread `dbPath` through `run*` signatures instead of the global. |
| F19 | ✅ Fixed (this session) | Security hygiene | internal/store/store.go:38-63 | High | S | `store.Open` calls `sql.Open` then `s.migrate()` (file created on first `Exec`), and only called `os.Chmod(path, 0o600)` afterward. Reproduced directly: under `umask 0002`, the file was `0644` (world-readable) in the window between creation and chmod on every `backup`/`restore`/`list`/`rotate` run against a not-yet-existing DB. | Fixed: `Open` now pre-creates the file via `os.OpenFile(path, os.O_RDWR\|os.O_CREATE, 0o600)` (and re-chmods for pre-existing files with looser permissions) before `sql.Open`/`migrate` ever touch it, closing the window. Verified: `TestOpenNeverCreatesFileUnderLoosePermissions` in `store_test.go` opens a fresh DB under `umask 0002` and asserts `0600` immediately. |
| F20 | ✅ Fixed (this session) | Consistency rot / reuse | cmd/doppler-backup/main.go:106-166 | Medium | S | `resolvePassphrase`, `resolveEncryptPassphrase`, `resolveNewPassphrase` (current shape post-dates the 2026-07-10 audit) duplicated: check flag value, check `term.IsTerminal`, error via `errPassphraseRequired`, prompt, reject blank — differing only in strength validation and confirmation. | Fixed: all three now delegate to a shared `resolveWithPrompt(flagValue, promptLabel, flagName string, validate func(string) error, confirmLabel string) (string, error)`, parameterized by a `validate` func (`noopValidate` or `validatePassphraseStrength`) and an optional confirmation prompt label. Verified: existing `TestResolvePassphrase`/`TestResolveEncryptPassphrase`/`TestResolveNewPassphrase`/`TestNonInteractivePassphraseRequired` all pass unchanged, confirming behavior parity. |
| F21 | **NEW** | Consistency rot | internal/store/store.go:64 and :115 | Low | S | Scrypt's legacy "interactive" defaults (`32768, 8, 1`) are hardcoded in two raw SQL DDL strings (`CREATE TABLE` default, `ALTER TABLE ADD COLUMN` backfill), and mirrored again in `store_test.go:11,267` and `crypto.go:29`'s comment. Four places that could drift with no compiler check. | Not urgent (historical constants that must never change), but a named Go constant interpolated into both DDL strings would remove the duplication risk. |
| F14 | Open (carried forward, unchanged, non-issue at current scale) | Performance | internal/crypto/crypto.go:88-98 (`newGCM`) | Low | — | Rebuilds the AES block cipher + GCM wrapper on every `Encrypt`/`Decrypt` call rather than caching per key. Immaterial — call volume is bounded by configs-per-run, not a hot loop. | No action needed; flagged so it isn't copy-pasted into a hot path elsewhere unnoticed. |
| F15 | Open (carried forward, unchanged) | Observability | cmd/doppler-backup/main.go:269,275 | Low | — | Backup failures print human text to stderr (`skipping project %s: %v`) rather than structured logs — fine for manual/cron use with captured output, no machine-parseable failure detail. | Only worth addressing if a future requirement needs machine-readable failure reporting. |
| F22 | **NEW** | Test debt | cmd/doppler-backup/main_test.go:272-318 | Low | S | `TestRestoreCleansUpTempFileOnSignal` polls a file for up to 5s in 20ms increments and re-execs the test binary to catch a SIGINT race — more flake-prone under CI contention than the rest of the (fast, deterministic) suite. | Leave as-is unless observed to flake; it's the only way to exercise this path. Noted so a future flaky-test report isn't a mystery. |
| F16 | Open (carried forward, re-verified, no drift) | Documentation drift | README.md:13, go.mod:3 | Low | — | README says "Go 1.26+"; go.mod now pins `go 1.26.5` (bumped since the prior audit's `1.26.4`, per F11). Still consistent. | Keep in sync on future toolchain bumps. |
| F17 | Open (carried forward, unchanged, expected) | Test debt (very minor) | cmd/doppler-backup/main.go:88-104 (`main`) | Low | — | `main()` itself is untested, as typical for Go `main` functions — all logic lives in the tested `run*` functions it calls. | No action; noted for completeness. |
| F18 | Improved — downgraded to no-action | Config debt | testresults/, godocs/ | Low | — | Previously flagged because `testresults/*.json` was empty on all recorded runs (root cause was F03). Now: 5 runs on disk, 44–58KB each, non-empty; `godocs/index.html` is current as of the latest `build.sh` run. No longer stale. | None. |

## Top 5 — fix these first

1. ~~**F19 — chmod-before-create for the backup DB.**~~ ✅ Fixed (this
   session). Was the clearest concrete risk found in either audit round: a
   multi-user host briefly exposed the backup file (ciphertext +
   project/config names, not decryptable without the passphrase, but still
   metadata) to other local accounts on every invocation against a
   not-yet-existing DB. `store.Open` now pre-creates the file at `0600`
   before `sql.Open`/`migrate` touch it.
2. ~~**F20 — collapse the three passphrase resolvers.**~~ ✅ Fixed (this
   session). All three now delegate to a shared `resolveWithPrompt` helper;
   a fourth passphrase-consuming command or a prompt-UX change no longer
   means copy-pasting a fourth variant or editing three functions in
   lockstep.
3. **F13 — stop mutating `dbPath` as a global in tests.** Held over from
   2026-07-10, still unaddressed, still cheap to fix before someone adds
   `t.Parallel()` and gets a confusing intermittent failure.
4. **F21 — name the scrypt legacy-default constant.** Cheap, bundle with
   F19 while `store.go` is already open.
5. **F22 — no action required, but keep in mind.** Not a code fix; listed
   as a Top 5 item only in the sense of "know this before you see a flaky
   CI run and go hunting."

## Quick wins

- [x] F19: Pre-create the backup DB file at `0o600` before `sql.Open`/migrate
      (High severity, S effort) — fixed this session.
- [ ] F21: Extract `32768, 8, 1` into a named constant shared by both DDL
      statements (Low severity, S effort)
- [ ] F13: Thread `dbPath` through `run*` signatures instead of a package
      global (Low-Medium severity, S-M effort)

## Things that look bad but are actually fine

Carried forward from 2026-07-10 (still accurate, re-checked against
current code) — `dopplerClient` living in `main` rather than
`internal/doppler`, `crypto.Decrypt` collapsing wrong-passphrase and
corrupted-ciphertext into one error, `RotateKey` loading all snapshots into
memory before re-encrypting (correctness-over-scalability trade,
appropriate at this project's size), no retry/backoff around `exec.Command`
calls, and `main.go`'s length (now 542 lines, up from 337, but still four
independent well-decomposed command blocks — see below for the updated
version of this point).

New this session:

- **`main.go` is 542 lines**, up from 337 at the prior audit and now
  technically over the 500-line "god file" threshold. Still four
  independent cobra subcommand wirings plus small shared passphrase
  helpers; no function itself is oversized and there's no hidden coupling
  between the command blocks (the growth since 2026-07-10 is the version
  check, passphrase strength/prompt logic, and rotate's confirmation flow —
  all legitimate feature growth, not sprawl). Splitting into per-command
  files would be file-count churn, not a real improvement, at this size.
  Worth re-checking again if it crosses ~700 lines.
- **`crypto.Params` and `store.KDFParams` are structurally identical
  structs requiring explicit conversion.** Looks like duplicate type
  definitions, but `store.go:28-31` documents it as a deliberate layering
  boundary: `store` persists `N/R/P` with no opinion on their
  cryptographic meaning, so it doesn't import `crypto`. Legitimate per
  CLAUDE.md's "store only ever sees ciphertext" rule.
- **`golang.org/x/crypto` still trips `GO-2026-5932`** (unmaintained
  `openpgp` subpackage) per `govulncheck`. Same as F12 in the prior audit —
  this project only ever imports `golang.org/x/crypto/scrypt`. Re-verified
  with `-show verbose`: 0 vulnerabilities in code actually called.
- **`restore`'s temp file gets `tmp.Chmod(0o600)` explicitly
  (`main.go:399`) even though `os.CreateTemp` already defaults to `0600`
  on Unix.** Redundant-looking, but harmless defense-in-depth for a
  plaintext-secrets file.
- **No `--restore-all` / bulk-restore mode.** README and CLAUDE.md both
  state this is intentional: blindly overwriting every config at once is
  more dangerous than the problem the tool solves.

## Open questions for the maintainer

- Is multi-user host access to the machine running `doppler-backup` a
  scenario worth defending against (relevant to F19's severity), or is
  this tool only ever expected to run on single-user machines/CI where the
  chmod race is moot?
- Is there an intended future where tests run with `t.Parallel()`
  (relevant to F13, open since 2026-07-10), or is the single-threaded test
  suite a permanent choice for this project's size?
- `artifacts/` now holds dated audit snapshots (`TECH_DEBT_AUDIT_2026_07_10.md`)
  alongside `godocs/`/`testresults/` as gitignored build output. Should
  future audit runs keep writing the living document to repo-root
  `TECH_DEBT_AUDIT.md` (as this one does) and let `build.sh` or a similar
  step snapshot dated copies into `artifacts/`, or should the dated
  snapshot under `artifacts/` be treated as the sole source of truth
  instead of a root-level file? Assumed the former for this run.
