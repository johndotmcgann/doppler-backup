package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// pkgGroupAssign matches the ROOT_PKGS/INTERNAL_PKGS assignments in godocs.sh.
var pkgGroupAssign = regexp.MustCompile(`^(ROOT_PKGS|INTERNAL_PKGS)=.*$`)

// godocsPackageGrouping returns the ROOT_PKGS and INTERNAL_PKGS assignment
// lines from godocs.sh verbatim, so tests exercise the real shell code.
func godocsPackageGrouping(t *testing.T) string {
	t.Helper()

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot determine location of test file")
	}
	dir := filepath.Dir(thisFile)
	var script string
	for {
		path := filepath.Join(dir, "godocs.sh")
		if b, err := os.ReadFile(path); err == nil {
			script = string(b)
			break
		}
		if parent := filepath.Dir(dir); parent != dir {
			dir = parent
			continue
		}
		t.Fatal("godocs.sh not found above test file")
	}

	var lines []string
	for _, line := range strings.Split(script, "\n") {
		if pkgGroupAssign.MatchString(strings.TrimSpace(line)) {
			lines = append(lines, line)
		}
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 ROOT_PKGS/INTERNAL_PKGS assignments in godocs.sh, found %d", len(lines))
	}
	return strings.Join(lines, "\n")
}

// TestGodocsPackageGroupingSurvivesEmptyGroup runs godocs.sh's ROOT_PKGS and
// INTERNAL_PKGS assignments under the script's own `set -eo pipefail` settings
// with `go list` stubbed out. Either grep exits 1 when a group has no members
// (for example every package lives under internal/), and without an explicit
// `|| true` guard `set -e` would abort the whole script, so both lines must
// guard themselves the same way.
func TestGodocsPackageGroupingSurvivesEmptyGroup(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skipf("bash not available: %v", err)
	}
	grouping := godocsPackageGrouping(t)

	tests := []struct {
		name         string
		goListOut    []string
		wantRoot     []string
		wantInternal []string
	}{
		{
			name: "root and internal packages",
			goListOut: []string{
				"example.com/mod",
				"example.com/mod/cmd/tool",
				"example.com/mod/internal/store",
			},
			wantRoot:     []string{"example.com/mod", "example.com/mod/cmd/tool"},
			wantInternal: []string{"example.com/mod/internal/store"},
		},
		{
			name:         "every package is internal",
			goListOut:    []string{"example.com/mod/internal/crypto", "example.com/mod/internal/store"},
			wantRoot:     nil,
			wantInternal: []string{"example.com/mod/internal/crypto", "example.com/mod/internal/store"},
		},
		{
			name:         "no packages are internal",
			goListOut:    []string{"example.com/mod", "example.com/mod/cmd/tool"},
			wantRoot:     []string{"example.com/mod", "example.com/mod/cmd/tool"},
			wantInternal: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			quoted := make([]string, 0, len(tt.goListOut))
			for _, pkg := range tt.goListOut {
				quoted = append(quoted, strconv.Quote(pkg))
			}

			script := strings.Join([]string{
				"set -eo pipefail",
				"go() { printf '%s\\n' " + strings.Join(quoted, " ") + "; }",
				grouping,
				`for pkg in $ROOT_PKGS; do printf 'root %s\n' "$pkg"; done`,
				`for pkg in $INTERNAL_PKGS; do printf 'internal %s\n' "$pkg"; done`,
			}, "\n")

			out, err := exec.Command(bash, "-c", script).CombinedOutput()
			if err != nil {
				t.Fatalf("package grouping aborted under set -eo pipefail: %v\nscript:\n%s\noutput:\n%s", err, script, out)
			}

			var root, internal []string
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				fields := strings.Fields(line)
				if len(fields) != 2 {
					continue
				}
				switch fields[0] {
				case "root":
					root = append(root, fields[1])
				case "internal":
					internal = append(internal, fields[1])
				}
			}

			if !slices.Equal(root, tt.wantRoot) {
				t.Errorf("ROOT_PKGS = %v, want %v", root, tt.wantRoot)
			}
			if !slices.Equal(internal, tt.wantInternal) {
				t.Errorf("INTERNAL_PKGS = %v, want %v", internal, tt.wantInternal)
			}
		})
	}
}
