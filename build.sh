#!/bin/sh
#
# Production build script for doppler-backup.
# Always builds and installs the executable to $HOME/Executables.
#
set -e

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

# ── Test results dir ──────────────────────────────────────────────────────────
printf '\nGenerating test results file.\n'
mkdir -p testresults
DT_STAMP=$(date "+%Y%m%d%H%M%S")
RESULTS_FILE="testresults/testresults_${DT_STAMP}.json"
touch "$RESULTS_FILE"

# Where are we in the file system
pwd

# ── Vet ───────────────────────────────────────────────────────────────────────
printf '\nVet the contents of the project.\n'
go vet ./...

# ── Test ──────────────────────────────────────────────────────────────────────
printf '\nRun tests; redirect output to .json file.\n'
go test -json ./... > "$RESULTS_FILE"

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

# ── Godoc ─────────────────────────────────────────────────────────────────────
printf '\nGenerating godoc HTML documentation.\n'
GODOC_BIN="$(go env GOPATH)/bin/godoc"
if [ ! -x "$GODOC_BIN" ]; then
    printf 'Warning: godoc not found at %s. Skipping documentation generation.\n' "$GODOC_BIN"
    printf 'Install with: go install golang.org/x/tools/cmd/godoc@latest\n'
else
    mkdir -p godocs
    MODULE="github.com/mcgannj/doppler-backup"
    GODOC_PORT=6162

    # Start godoc server in background
    "$GODOC_BIN" -http=":${GODOC_PORT}" &
    GODOC_PID=$!

    # Wait until godoc is ready (up to 15 seconds)
    printf 'Waiting for godoc server to be ready...\n'
    RETRIES=0
    until wget -q --spider "http://localhost:${GODOC_PORT}/pkg/${MODULE}/" 2>/dev/null; do
        RETRIES=$((RETRIES + 1))
        if [ "$RETRIES" -ge 15 ]; then
            printf 'Error: godoc server did not become ready after 15 seconds. Skipping.\n'
            kill "$GODOC_PID" 2>/dev/null
            GODOC_PID=""
            break
        fi
        sleep 1
    done

    # Mirror the module's package documentation to godocs/
    # Internal packages are not linked from the top-level page, so we use
    # go list to enumerate every package URL and feed them all to wget.
    if [ -n "$GODOC_PID" ]; then
        PACKAGE_URLS=$(go list ./... | sed "s|.*|http://localhost:${GODOC_PORT}/pkg/&/|")
        # shellcheck disable=SC2086
        wget --recursive \
             --no-parent \
             --page-requisites \
             --convert-links \
             --adjust-extension \
             --no-verbose \
             --no-host-directories \
             --no-clobber \
             --directory-prefix=godocs \
             --include-directories="/pkg/${MODULE},/lib/godoc,/src/${MODULE}" \
             $PACKAGE_URLS
    fi

    # Stop the godoc server
    kill "$GODOC_PID" 2>/dev/null
    wait "$GODOC_PID" 2>/dev/null || true

    # Generate a custom index.html that links to every package page
    printf 'Generating godocs/index.html\n'
    INDEX_FILE="godocs/index.html"
    cat > "$INDEX_FILE" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>doppler-backup &mdash; Package Documentation</title>
  <link rel="stylesheet" href="lib/godoc/style.css">
  <style>
    body { padding: 1em 2em; font-family: sans-serif; }
    h1   { border-bottom: 1px solid #ccc; padding-bottom: 0.3em; }
    ul   { list-style: none; padding: 0; }
    li   { margin: 0.3em 0; }
    a    { text-decoration: none; color: #375EAB; }
    a:hover { text-decoration: underline; }
    .section { margin-top: 1.5em; }
    .section h2 { font-size: 1.1em; color: #555; margin-bottom: 0.4em; }
  </style>
</head>
<body>
  <h1>doppler-backup &mdash; Package Documentation</h1>
  <p>Generated by <code>godoc</code>. Click a package to view its documentation.</p>
HTMLEOF

    # Group packages: root vs internal
    ROOT_PKGS=$(go list ./... | grep -v "/internal/")
    INTERNAL_PKGS=$(go list ./... | grep "/internal/" || true)

    if [ -n "$ROOT_PKGS" ]; then
        printf '  <div class="section"><h2>Root packages</h2><ul>\n' >> "$INDEX_FILE"
        for PKG in $ROOT_PKGS; do
            LABEL=$(echo "$PKG" | sed "s|${MODULE}/||;s|${MODULE}|main|")
            HREF="pkg/${PKG}/index.html"
            printf '    <li><a href="%s">%s</a></li>\n' "$HREF" "$LABEL" >> "$INDEX_FILE"
        done
        printf '  </ul></div>\n' >> "$INDEX_FILE"
    fi

    if [ -n "$INTERNAL_PKGS" ]; then
        printf '  <div class="section"><h2>Internal packages</h2><ul>\n' >> "$INDEX_FILE"
        for PKG in $INTERNAL_PKGS; do
            LABEL=$(echo "$PKG" | sed "s|${MODULE}/||")
            HREF="pkg/${PKG}/index.html"
            printf '    <li><a href="%s">%s</a></li>\n' "$HREF" "$LABEL" >> "$INDEX_FILE"
        done
        printf '  </ul></div>\n' >> "$INDEX_FILE"
    fi

    cat >> "$INDEX_FILE" << HTMLEOF
</body>
</html>
HTMLEOF

    printf 'Documentation written to godocs/\n'
fi

printf '\nCompleted production build of doppler-backup.\n'
