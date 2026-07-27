# doppler-backup

Emergency backup/restore for [Doppler](https://www.doppler.com) secrets.

Doppler keeps per-secret version history and an activity log, but **it
cannot recover a deleted project**. `doppler-backup` is a local safety net:
it snapshots every secret in every project/config into a SQLite database,
encrypted at rest with AES-256-GCM under a passphrase you choose, and can
restore any snapshot back into Doppler.

## Who may need this?

Anyone using the 'developer' Doppler account for secrets management
with applications (e.g. solo developers, very small teams).
This application was developed against the features of a
'developer' Doppler account.

There may be features in a Doppler 'teams' or 'enterprise'
account that may be suitable for inclusion in this type of application.
I'm happy for this project to be cloned or forked in that
regard for someone to add missing features for the
'teams' or 'enterprise' Doppler account types.

## Prerequisites

- The [`doppler` CLI](https://docs.doppler.com/docs/install-cli), version
  3.76.0 or newer, installed and authenticated (`doppler login`) —
  `doppler-backup` shells out to it rather than talking to the Doppler API
  directly. `backup` and `restore` check the installed CLI's version up
  front and fail fast with a clear error if it's too old.
- Go 1.26+ — only needed if building from source; skip it if you're using a
  prebuilt binary.

## Install

### Download a prebuilt binary

Each [GitHub Release](https://github.com/johndotmcgann/doppler-backup/releases/latest)
has binaries for Linux, macOS, and Windows attached. Download the asset that
matches your OS/architecture, e.g. for release `vX.Y.Z`:

| OS      | Architecture   | Asset                                  |
|---------|----------------|-----------------------------------------|
| macOS   | Apple Silicon  | `doppler-backup-vX.Y.Z-darwin-arm64`   |
| macOS   | Intel          | `doppler-backup-vX.Y.Z-darwin-amd64`   |
| Linux   | amd64          | `doppler-backup-vX.Y.Z-linux-amd64`    |
| Linux   | arm64          | `doppler-backup-vX.Y.Z-linux-arm64`    |
| Windows | amd64          | `doppler-backup-vX.Y.Z-windows-amd64.exe` |

On Linux/macOS, mark the download executable and move it onto your `$PATH`:

```sh
chmod +x doppler-backup-vX.Y.Z-<os>-<arch>
mv doppler-backup-vX.Y.Z-<os>-<arch> /usr/local/bin/doppler-backup
```

### Build from source

```sh
git clone https://github.com/johndotmcgann/doppler-backup.git
cd doppler-backup
make build          # produces bin/doppler-backup
make install         # go install into $GOPATH/bin
```

## Usage

All commands accept `--db PATH` to choose the SQLite database file
(default `./doppler-backup.db`). The database is created automatically on
first use and locked down to owner-only (`0600`) permissions.

A passphrase is always required to encrypt or decrypt the backup database —
there is no default and no environment-variable fallback. Pass it via
`--passphrase` (or `--old-passphrase`/`--new-passphrase` for `rotate`), or
omit the flag when running interactively to be prompted for it without the
input being echoed back. Running non-interactively (e.g. from cron) without
the flag is an error, so unattended use must always pass the flag
explicitly.

Passphrases used to **encrypt** (`backup`, and `rotate`'s
`--new-passphrase`) must be at least 12 characters. Length, not
character-class complexity, is what protects against offline brute force
here — this passphrase feeds directly into scrypt and protects a static
file an attacker with a copy can attack with no rate limiting — so a long
random passphrase from a password manager, or a multi-word Diceware-style
phrase, is both easier to type and stronger than a short "complex" one.
Passphrases used only to **decrypt** existing data (`restore`, and
`rotate`'s `--old-passphrase`) are accepted as-is regardless of length, so
databases created before this minimum was introduced remain restorable; run
`rotate` to move such a database onto a compliant new passphrase.

### Backup

Snapshot every project and config visible to your Doppler token:

```sh
doppler-backup backup --passphrase '<your passphrase>'
```

Limit to a single project:

```sh
doppler-backup backup --project my-project --passphrase '<your passphrase>'
```

A failure on one config (e.g. a locked or inaccessible config) is logged
and skipped rather than aborting the whole run. The command exits non-zero
only if every backup attempt failed.

### List snapshots

```sh
doppler-backup list
doppler-backup list --project my-project
```

Shows snapshot id, project, config, and timestamp (no passphrase needed —
listing doesn't decrypt anything).

### Restore

Restore the most recent snapshot for a project/config:

```sh
doppler-backup restore --project my-project --config prd --passphrase '<your passphrase>'
```

Restore a specific snapshot by id (see `doppler-backup list`):

```sh
doppler-backup restore --project my-project --config prd --snapshot 12 --passphrase '<your passphrase>'
```

`--project` and `--config` must be given explicitly — there is no
"restore everything" mode, since blindly overwriting every config at once
is more dangerous than the problem this tool solves. Restoring into a
brand-new project (e.g. after recreating one that was deleted) works the
same way: create the project/config in Doppler first, then restore into
it.

A wrong passphrase fails cleanly with `incorrect passphrase or corrupted
snapshot` rather than silently writing garbage secrets.

### Rotate passphrase

Re-encrypt every stored snapshot under a new passphrase, invalidating the
old one:

```sh
doppler-backup rotate --old-passphrase '<current passphrase>' --new-passphrase '<new passphrase>'
```

This decrypts every snapshot with the old passphrase and re-encrypts it
under a freshly generated salt and the new passphrase, all inside a single
transaction — either everything is rotated or nothing is. Before making any
changes it copies the database to `<db>.bak-<unix timestamp>` as a safety
net; delete that copy once you've confirmed the new passphrase works.

## How it works

- **Backup**: enumerates projects (`doppler projects`) and configs
  (`doppler configs`), downloads each config's secrets
  (`doppler secrets download --json`), encrypts the JSON blob, and stores
  it as one row per project/config/timestamp.
- **Restore**: decrypts the chosen snapshot, writes it to a temporary
  `0600` file, and uploads it with `doppler secrets upload`. The temp file
  is created in `/dev/shm` (tmpfs) when available, falling back to the OS
  default temp directory otherwise, and is removed as soon as the upload
  finishes. A `SIGINT`/`SIGTERM` handler also removes it if you interrupt
  a restore mid-flight. None of this protects against `SIGKILL` or a hard
  crash between the write and the cleanup — in that narrow window,
  decrypted secrets can be left on disk (or in tmpfs, which itself can be
  swapped to disk on memory pressure unless swap is disabled).
- **Encryption**: a random salt is generated once per database and stored
  in a `meta` table. Every run derives a 32-byte key from your passphrase
  and that salt via `scrypt`, then encrypts each snapshot with AES-256-GCM
  and a fresh random nonce. Losing the passphrase means losing access to
  every snapshot in that database — there is no recovery mechanism.
- Doppler's computed `DOPPLER_PROJECT` / `DOPPLER_CONFIG` /
  `DOPPLER_ENVIRONMENT` values are stripped before snapshotting since
  they describe the target config rather than being real secrets.

## Notes

- No built-in scheduling — run `doppler-backup backup` from cron or a
  similar scheduler for regular snapshots.
