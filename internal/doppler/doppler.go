// Package doppler wraps the `doppler` CLI (assumed installed and
// authenticated on the host) rather than reimplementing Doppler's API.
package doppler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

const pageSize = 100

// MinVersion is the oldest doppler CLI version this tool is developed and
// tested against. CheckMinVersion enforces it as a floor, since the JSON
// output shapes this package parses (projects/configs/secrets) could change
// upstream without this tool noticing otherwise.
const MinVersion = "3.76.0"

// computedKeys are read-only values Doppler injects into every download;
// they describe the target config rather than being real secrets, so they
// are not snapshotted or re-uploaded.
var computedKeys = map[string]bool{
	"DOPPLER_PROJECT":     true,
	"DOPPLER_CONFIG":      true,
	"DOPPLER_ENVIRONMENT": true,
}

type Project struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Config struct {
	Name        string `json:"name"`
	Environment string `json:"environment"`
	Project     string `json:"project"`
}

type Client struct {
	runFunc func(args ...string) ([]byte, error)
}

func NewClient() *Client {
	return &Client{runFunc: runDoppler}
}

func (c *Client) run(args ...string) ([]byte, error) {
	return c.runFunc(args...)
}

func runDoppler(args ...string) ([]byte, error) {
	cmd := exec.Command("doppler", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("doppler %v: %w: %s", args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// ListProjects returns every project visible to the authenticated token,
// paging through results since the CLI caps a single page at 100.
func (c *Client) ListProjects() ([]Project, error) {
	var all []Project
	for page := 1; ; page++ {
		out, err := c.run("projects", "--json", "-n", fmt.Sprint(pageSize), "--page", fmt.Sprint(page))
		if err != nil {
			return nil, fmt.Errorf("list projects: %w", err)
		}
		var batch []Project
		if err := json.Unmarshal(out, &batch); err != nil {
			return nil, fmt.Errorf("parse projects: %w", err)
		}
		all = append(all, batch...)
		if len(batch) < pageSize {
			break
		}
	}
	return all, nil
}

// ListConfigs returns every config under the given project.
func (c *Client) ListConfigs(project string) ([]Config, error) {
	var all []Config
	for page := 1; ; page++ {
		out, err := c.run("configs", "-p", project, "--json", "-n", fmt.Sprint(pageSize), "--page", fmt.Sprint(page))
		if err != nil {
			return nil, fmt.Errorf("list configs for project %q: %w", project, err)
		}
		var batch []Config
		if err := json.Unmarshal(out, &batch); err != nil {
			return nil, fmt.Errorf("parse configs for project %q: %w", project, err)
		}
		all = append(all, batch...)
		if len(batch) < pageSize {
			break
		}
	}
	return all, nil
}

// DownloadSecrets fetches all secrets for a project/config as a flat
// key-value map, with Doppler's computed DOPPLER_* keys filtered out.
func (c *Client) DownloadSecrets(project, config string) (map[string]string, error) {
	out, err := c.run("secrets", "download", "--no-file", "--json", "-p", project, "-c", config)
	if err != nil {
		return nil, fmt.Errorf("download secrets for %s/%s: %w", project, config, err)
	}
	var secrets map[string]string
	if err := json.Unmarshal(out, &secrets); err != nil {
		return nil, fmt.Errorf("parse secrets for %s/%s: %w", project, config, err)
	}
	for k := range computedKeys {
		delete(secrets, k)
	}
	return secrets, nil
}

// UploadSecrets pushes the JSON secrets file at path into a project/config.
func (c *Client) UploadSecrets(project, config, path string) error {
	if _, err := c.run("secrets", "upload", path, "-p", project, "-c", config); err != nil {
		return fmt.Errorf("upload secrets to %s/%s: %w", project, config, err)
	}
	return nil
}

// Version returns the installed doppler CLI's version, e.g. "3.76.0".
func (c *Client) Version() (string, error) {
	out, err := c.run("--version")
	if err != nil {
		return "", fmt.Errorf("doppler CLI version: %w", err)
	}
	v := strings.TrimSpace(string(out))
	v = strings.TrimPrefix(v, "v")
	return v, nil
}

// parseVersion parses a "major.minor.patch" string into its three integer
// components.
func parseVersion(v string) ([3]int, error) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("expected major.minor.patch, got %q", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("expected major.minor.patch, got %q", v)
		}
		out[i] = n
	}
	return out, nil
}

// CheckMinVersion returns an error unless installed parses as a version
// greater than or equal to MinVersion.
func CheckMinVersion(installed string) error {
	got, err := parseVersion(installed)
	if err != nil {
		return fmt.Errorf(
			"could not parse doppler CLI version %q; doppler CLI %s or newer is required "+
				"— upgrade with your package manager or see https://docs.doppler.com/docs/install-cli",
			installed, MinVersion)
	}
	want, err := parseVersion(MinVersion)
	if err != nil {
		return fmt.Errorf("parse MinVersion %q: %w", MinVersion, err)
	}
	for i := range got {
		if got[i] != want[i] {
			if got[i] > want[i] {
				return nil
			}
			return fmt.Errorf(
				"doppler CLI %s or newer is required (found %s) — upgrade with your package "+
					"manager or see https://docs.doppler.com/docs/install-cli",
				MinVersion, installed)
		}
	}
	return nil
}
