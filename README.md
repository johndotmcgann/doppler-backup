# doppler-backup

Emergency backup/restore for [Doppler](https://www.doppler.com) secrets.

Doppler keeps per-secret version history and an activity log, but **it
cannot recover a deleted project**. `doppler-backup` is a local safety net:
it snapshots every secret in every project/config into a SQLite database,
encrypted at rest with AES-256-GCM under a passphrase you choose, and can
restore any snapshot back into Doppler.

## Prerequisites

- Go 1.26+
- The [`doppler` CLI](https://docs.doppler.com/docs/install-cli) installed
  and authenticated (`doppler login`) — `doppler-backup` shells out to it
  rather than talking to the Doppler API directly.

## Build

```sh
make build          # produces bin/doppler-backup
make install         # go install into $GOPATH/bin
```

## Usage

All commands accept `--db PATH` to choose the SQLite database file
(default `./doppler-backup.db`). The database is created automatically on
first use and locked down to owner-only (`0600`) permissions.

`--passphrase` (and `--old-passphrase`/`--new-passphrase` for `rotate`) is
optional. If omitted and run from a terminal, you'll be prompted for it
without the input being echoed back; leaving that prompt blank, or running
non-interactively (e.g. from cron) without the flag, falls back to the
default passphrase `doppler_backup`.

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
  `0600` file, and uploads it with `doppler secrets upload`.
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
