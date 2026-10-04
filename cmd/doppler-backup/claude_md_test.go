package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeMdGeneratedArtifactAttribution guards the Notes bullet in CLAUDE.md
// against claiming godocs/ comes from build.sh: build.sh only prints a pointer
// to godocs.sh, which is the script that actually writes godocs/.
func TestClaudeMdGeneratedArtifactAttribution(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join("..", "..", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		return string(b)
	}

	claudeMD := read("CLAUDE.md")
	buildSh := read("build.sh")
	godocsSh := read("godocs.sh")

	if !strings.Contains(buildSh, "mkdir -p testresults") {
		t.Error("build.sh no longer creates testresults/; CLAUDE.md needs updating")
	}
	if !strings.Contains(godocsSh, "mkdir -p godocs") {
		t.Error("godocs.sh no longer creates godocs/; CLAUDE.md needs updating")
	}
	if strings.Contains(buildSh, "mkdir -p godocs") {
		t.Error("build.sh now creates godocs/; CLAUDE.md's attribution needs updating")
	}
	if !strings.Contains(claudeMD, "`testresults/` (from `build.sh`)") {
		t.Error("CLAUDE.md Notes should attribute testresults/ to build.sh")
	}
	if !strings.Contains(claudeMD, "`godocs/` (from `godocs.sh`)") {
		t.Error("CLAUDE.md Notes should attribute godocs/ to godocs.sh")
	}
}
