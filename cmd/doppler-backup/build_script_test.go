package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readBuildScript returns the contents of the repository's production build
// script.
func readBuildScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "build.sh")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}

// buildScriptHeader returns the comment block that follows the shebang in
// build.sh, i.e. the documentation a reader sees first.
func buildScriptHeader(t *testing.T) string {
	t.Helper()
	lines := strings.Split(readBuildScript(t), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "#!") {
		t.Fatalf("build.sh: expected a shebang on line 1, got %q", lines[0])
	}
	var header []string
	for _, line := range lines[1:] {
		if !strings.HasPrefix(line, "#") {
			break
		}
		header = append(header, line)
	}
	if len(header) == 0 {
		t.Fatal("build.sh: expected a comment header after the shebang")
	}
	return strings.Join(header, "\n")
}

// TestBuildScriptHeaderMatchesBehavior guards the header comment against
// drifting away from what the script actually does. build.sh vets, tests, and
// builds to bin/; it no longer installs a copy of the executable anywhere.
func TestBuildScriptHeaderMatchesBehavior(t *testing.T) {
	script := readBuildScript(t)
	header := buildScriptHeader(t)

	if !strings.Contains(script, `-o "bin/doppler-backup"`) {
		t.Fatal("build.sh no longer builds to bin/doppler-backup; " +
			"this test needs updating to match the script's new behaviour")
	}
	for _, gone := range []string{"go install", "$HOME/Executables"} {
		if strings.Contains(script, gone) {
			t.Fatalf("build.sh references %q; if the install step is back, "+
				"update this test and the header comment accordingly", gone)
		}
	}

	if lower := strings.ToLower(header); strings.Contains(lower, "install") {
		t.Errorf("build.sh header claims an install step, which the script no "+
			"longer performs:\n%s", header)
	}
	if !strings.Contains(header, "bin/") {
		t.Errorf("build.sh header does not mention the bin/ output directory:\n%s", header)
	}
}
