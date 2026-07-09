package doppler

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestListProjectsPaginates(t *testing.T) {
	var gotPages []string
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		gotPages = append(gotPages, pageArg(args))
		page := pageArg(args)
		if page == "1" {
			return []byte(jsonProjects(pageSize, "proj")), nil
		}
		return []byte(jsonProjects(1, "proj")), nil
	}}

	got, err := c.ListProjects()
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("expected %d projects, got %d", pageSize+1, len(got))
	}
	if len(gotPages) != 2 || gotPages[0] != "1" || gotPages[1] != "2" {
		t.Fatalf("expected pages [1 2], got %v", gotPages)
	}
}

func TestListProjectsPropagatesRunError(t *testing.T) {
	wantErr := errors.New("boom")
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return nil, wantErr
	}}

	if _, err := c.ListProjects(); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

func TestListProjectsPropagatesParseError(t *testing.T) {
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return []byte("not json"), nil
	}}

	if _, err := c.ListProjects(); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestListConfigsPaginatesAndForwardsProject(t *testing.T) {
	var gotProjectArgs []string
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		gotProjectArgs = append(gotProjectArgs, projectArg(args))
		if pageArg(args) == "1" {
			return []byte(jsonConfigs(pageSize)), nil
		}
		return []byte(jsonConfigs(1)), nil
	}}

	got, err := c.ListConfigs("my-project")
	if err != nil {
		t.Fatalf("list configs: %v", err)
	}
	if len(got) != pageSize+1 {
		t.Fatalf("expected %d configs, got %d", pageSize+1, len(got))
	}
	for _, p := range gotProjectArgs {
		if p != "my-project" {
			t.Fatalf("expected project arg 'my-project', got %q", p)
		}
	}
}

func TestListConfigsPropagatesParseError(t *testing.T) {
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return []byte("not json"), nil
	}}

	if _, err := c.ListConfigs("proj"); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestDownloadSecretsStripsComputedKeys(t *testing.T) {
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return []byte(`{"DOPPLER_PROJECT":"p","DOPPLER_CONFIG":"c","DOPPLER_ENVIRONMENT":"e","API_KEY":"secret"}`), nil
	}}

	got, err := c.DownloadSecrets("p", "c")
	if err != nil {
		t.Fatalf("download secrets: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected computed keys stripped, got %v", got)
	}
	if got["API_KEY"] != "secret" {
		t.Fatalf("expected API_KEY preserved, got %v", got)
	}
}

func TestDownloadSecretsPropagatesParseError(t *testing.T) {
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return []byte("not json"), nil
	}}

	if _, err := c.DownloadSecrets("p", "c"); err == nil {
		t.Fatalf("expected parse error")
	}
}

func TestUploadSecretsForwardsArgs(t *testing.T) {
	var gotArgs []string
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		gotArgs = args
		return nil, nil
	}}

	if err := c.UploadSecrets("proj", "cfg", "/tmp/secrets.json"); err != nil {
		t.Fatalf("upload secrets: %v", err)
	}

	joined := strings.Join(gotArgs, " ")
	for _, want := range []string{"/tmp/secrets.json", "proj", "cfg"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected args %v to contain %q", gotArgs, want)
		}
	}
}

func TestUploadSecretsPropagatesRunError(t *testing.T) {
	wantErr := errors.New("boom")
	c := &Client{runFunc: func(args ...string) ([]byte, error) {
		return nil, wantErr
	}}

	if err := c.UploadSecrets("proj", "cfg", "/tmp/secrets.json"); !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped %v, got %v", wantErr, err)
	}
}

// TestRunDopplerCapturesStdoutAndStderr exercises the real exec.Command
// plumbing in runDoppler (not just the higher-level fakes above) against a
// fixture script installed as "doppler" on PATH.
func TestRunDopplerCapturesStdoutAndStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "doppler")
	contents := "#!/bin/sh\n" +
		"if [ \"$1\" = \"succeed\" ]; then\n" +
		"  echo -n 'ok-stdout'\n" +
		"  exit 0\n" +
		"fi\n" +
		"echo -n 'boom-stderr' 1>&2\n" +
		"exit 1\n"
	if err := os.WriteFile(script, []byte(contents), 0o755); err != nil {
		t.Fatalf("write fixture script: %v", err)
	}

	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	out, err := runDoppler("succeed")
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if string(out) != "ok-stdout" {
		t.Fatalf("expected stdout 'ok-stdout', got %q", out)
	}

	_, err = runDoppler("fail")
	if err == nil {
		t.Fatalf("expected error from failing command")
	}
	if !strings.Contains(err.Error(), "boom-stderr") {
		t.Fatalf("expected error to include stderr content, got %v", err)
	}
}

func pageArg(args []string) string {
	for i, a := range args {
		if a == "--page" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func projectArg(args []string) string {
	for i, a := range args {
		if a == "-p" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func jsonProjects(n int, prefix string) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"id":"%s-%d","name":"%s-%d"}`, prefix, i, prefix, i)
	}
	b.WriteString("]")
	return b.String()
}

func jsonConfigs(n int) string {
	var b strings.Builder
	b.WriteString("[")
	for i := range n {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"cfg-%d","environment":"dev","project":"proj"}`, i)
	}
	b.WriteString("]")
	return b.String()
}
