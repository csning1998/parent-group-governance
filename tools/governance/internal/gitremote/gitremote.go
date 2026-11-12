// Package gitremote derives the GitLab host and project path from the origin remote of a repository.
package gitremote

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// ErrUnsupportedRemote indicates an origin URL lacking a host authority or a group path prefix.
var ErrUnsupportedRemote = errors.New("gitremote: the origin URL names no GitLab host and project path below a group")

// Remote holds the GitLab hostname and project path parsed from a Git remote URL.
type Remote struct {
	Host        string
	ProjectPath string
}

// Parse extracts the GitLab hostname and project path from an SSH or HTTPS remote URL.
func Parse(url string) (Remote, error) {
	var authority, path string
	scheme, rest, hasScheme := strings.Cut(url, "://")
	switch {
	case hasScheme && scheme != "" && scheme != "file":
		authority, path, _ = strings.Cut(rest, "/")
	case !hasScheme && !strings.HasPrefix(url, "/"):
		authority, path, _ = strings.Cut(url, ":")
	}
	authority = authority[strings.LastIndex(authority, "@")+1:]
	host, _, _ := strings.Cut(authority, ":")
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	if host == "" || !strings.Contains(path, "/") {
		return Remote{}, fmt.Errorf("%w: %q", ErrUnsupportedRemote, url)
	}
	return Remote{Host: host, ProjectPath: path}, nil
}

// Resolve reads the origin URL of the repository at dir.
func Resolve(ctx context.Context, dir string) (Remote, error) {
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return Remote{}, fmt.Errorf("gitremote: read the origin URL of %s: %w", dir, err)
	}
	return Parse(strings.TrimSpace(string(out)))
}

// WebURL returns the https URL of the GitLab host.
func (r Remote) WebURL() string {
	return "https://" + r.Host
}

// APIURL returns the REST API base URL of the GitLab host.
func (r Remote) APIURL() string {
	return r.WebURL() + "/api/v4"
}

// TopLevelGroup returns the root namespace segment of the project path.
func (r Remote) TopLevelGroup() string {
	group, _, _ := strings.Cut(r.ProjectPath, "/")
	return group
}
