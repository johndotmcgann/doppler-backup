#!/usr/bin/env bash
#
# Production build script for doppler-backup.
# Always builds and installs the executable to $HOME/Executables.
#
set -e
set -o pipefail

printf 'Commencing production build for doppler-backup.\n'

# ── Parameters ────────────────────────────────────────────────────────────────
BUMP=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --major)   BUMP="major" ;;
        --minor)   BUMP="minor" ;;
        --patch)   BUMP="patch" ;;
        *)         printf 'Unknown parameter: %s\n' "$1"; exit 1 ;;
    esac
    shift
done

# ── Version bump ──────────────────────────────────────────────────────────────
if [ -n "$BUMP" ]; then
    CURRENT_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
    MAJOR=$(printf '%s' "$CURRENT_TAG" | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)/\1/')
    MINOR=$(printf '%s' "$CURRENT_TAG" | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)/\2/')
    PATCH=$(printf '%s' "$CURRENT_TAG" | sed 's/v\([0-9]*\)\.\([0-9]*\)\.\([0-9]*\)/\3/')
    case "$BUMP" in
        major) MAJOR=$((MAJOR + 1)); MINOR=0; PATCH=0 ;;
        minor) MINOR=$((MINOR + 1)); PATCH=0 ;;
        patch) PATCH=$((PATCH + 1)) ;;
    esac
    NEW_TAG="v${MAJOR}.${MINOR}.${PATCH}"
    printf 'Bumping version %s -> %s\n' "$CURRENT_TAG" "$NEW_TAG"
    git tag -a "$NEW_TAG" -m "Release $NEW_TAG"
fi

# Where are we in the file system
pwd

# ── Vet ───────────────────────────────────────────────────────────────────────
printf '\nVet the contents of the project.\n'
go vet ./...

# ── Test ──────────────────────────────────────────────────────────────────────
# The results file is created only once vet has passed, so an empty/missing
# file unambiguously means "tests never ran" rather than looking like a
# recorded (but silently truncated) run.
printf '\nGenerating test results file.\n'
mkdir -p testresults
DT_STAMP=$(date "+%Y%m%d%H%M%S")
RESULTS_FILE="testresults/testresults_${DT_STAMP}.json"

printf '\nRun tests; tee output to .json file.\n'
go test -json ./... | tee "$RESULTS_FILE"

if [ ! -s "$RESULTS_FILE" ]; then
    printf '\nError: %s is empty; go test produced no output.\n' "$RESULTS_FILE"
    exit 1
fi

printf '\nReport on the test coverage.\n'
go test -cover ./...

# ── Git metadata ──────────────────────────────────────────────────────────────
GIT_TAG=$(git describe --tags --exact-match 2>/dev/null \
          || git describe --tags --abbrev=0 2>/dev/null \
          || echo "dev")

# ── Build ─────────────────────────────────────────────────────────────────────
printf '\nBuild executable version of software (version %s).\n' "$GIT_TAG"
mkdir -p bin
go build -v \
    -ldflags "-X main.Version=${GIT_TAG}" \
    -o "bin/doppler-backup" \
    ./cmd/doppler-backup

# Copy the binary to ~/Executables for use outside the project directory.
# Opt-in only: this step is specific to the maintainer's local setup.
if [ "${INSTALL_LOCAL:-0}" = "1" ]; then
    mkdir -p "$HOME/Executables"
    cp bin/doppler-backup "$HOME/Executables/doppler-backup"
    printf 'Copied binary to %s/Executables/doppler-backup\n' "$HOME"
fi

printf '\nRun the application with:\n'
printf '  ./bin/doppler-backup backup --passphrase <passphrase>\n'
printf '  ./bin/doppler-backup restore --project <p> --config <c> --passphrase <passphrase>\n'
printf '  ./bin/doppler-backup --version\n'

printf '\nCompleted production build of doppler-backup.\n'
printf 'For local godoc HTML docs, run ./godocs.sh separately.\n'
