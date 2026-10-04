package ci

import (
	"os"
	"strings"
	"testing"
)

// workflowJob returns the body of the named job in a GitHub Actions workflow.
// Job keys sit at the two-space indentation level under `jobs:`, and the
// steps of the current job are indented deeper than that, so the job ends at
// the next two-space key ending in a colon.
func workflowJob(t *testing.T, path, job string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var body []string
	inJob := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "  "+job+":" {
			inJob = true
			continue
		}
		if inJob && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			break
		}
		if inJob {
			body = append(body, line)
		}
	}
	if !inJob {
		t.Fatalf("job %q not found in %s", job, path)
	}
	return strings.Join(body, "\n")
}

// TestCIWorkflowRunsVulnCheck guards the vulnerability scan added for audit
// finding F01: CI runs govulncheck over the whole module in the same job as
// the tests, so a vulnerability this code can actually reach fails the build.
func TestCIWorkflowRunsVulnCheck(t *testing.T) {
	job := workflowJob(t, ".github/workflows/ci.yml", "test")

	found := false
	for _, line := range strings.Split(job, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "govulncheck") {
			if !strings.Contains(trimmed, "./...") {
				t.Errorf("govulncheck step does not scan the whole module: %q", trimmed)
			}
			found = true
		}
	}
	if !found {
		t.Errorf("job %q has no govulncheck step", "test")
	}

	if !strings.Contains(job, "go test ./...") {
		t.Errorf("job %q no longer runs go test ./...", "test")
	}
}
