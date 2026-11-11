package issuedtokens

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"text/template"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
)

//go:embed runner_config.toml.tmpl
var runnerConfigTemplate string

// ErrRunnerConfigExists marks a registration refused because config.toml already holds a runner token.
var ErrRunnerConfigExists = errors.New("issuedtokens: the runner config file exists")

// RunnerCreator creates a group runner and returns the runner authentication token.
type RunnerCreator interface {
	CreateGroupRunner(ctx context.Context, r gitlabapi.GroupRunner) (gitlabapi.CreatedRunner, error)
}

// GroupRunnerRegistration creates the group runner and writes the runner authentication token into config.toml.
type GroupRunnerRegistration struct {
	Config     GitLabGroupRunnerConfig
	GroupID    string
	ConfigPath string
	GitLab     RunnerCreator
}

// Run refuses an existing config.toml because a second registration leaves the earlier runner registered with a valid token.
func (r GroupRunnerRegistration) Run(ctx context.Context) (int, error) {
	if _, err := os.Stat(r.ConfigPath); err == nil {
		return 0, fmt.Errorf("%w: %s, delete the runner of the file and the file before a new registration", ErrRunnerConfigExists, r.ConfigPath)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return 0, fmt.Errorf("issuedtokens: inspect %s: %w", r.ConfigPath, err)
	}
	created, err := r.GitLab.CreateGroupRunner(ctx, gitlabapi.GroupRunner{
		GroupID:     r.GroupID,
		Description: r.Config.Description,
		TagList:     r.Config.TagList,
		Locked:      true,
		RunUntagged: true,
	})
	if err != nil {
		return 0, err
	}
	if err := writeRunnerConfig(r.ConfigPath, r.Config, created.Token); err != nil {
		return created.ID, fmt.Errorf("issuedtokens: runner %d exists in GitLab while %s stays unwritten, delete the runner before a retry: %w", created.ID, r.ConfigPath, err)
	}
	return created.ID, nil
}

// writeRunnerConfig renames a 0600 temporary file into place, which keeps a partial file away from the runner container.
func writeRunnerConfig(path string, cfg GitLabGroupRunnerConfig, token string) error {
	tmpl, err := template.New("config.toml").Parse(runnerConfigTemplate)
	if err != nil {
		return err
	}
	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, struct{ Name, URL, Token string }{cfg.Description, cfg.GitLabURL, token}); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".config.toml-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(rendered.Bytes()); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
