// Package doppler wraps the `doppler` CLI (assumed installed and
// authenticated on the host) rather than reimplementing Doppler's API.
package doppler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
)

const pageSize = 100

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

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) run(args ...string) ([]byte, error) {
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
