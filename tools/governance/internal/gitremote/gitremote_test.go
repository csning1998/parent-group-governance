package gitremote

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestParse(t *testing.T) {
	want := Remote{Host: "gitlab.example.com", ProjectPath: "example-group/example-subgroup/example-project"}
	for _, url := range []string{
		"git@gitlab.example.com:example-group/example-subgroup/example-project.git",
		"https://gitlab.example.com/example-group/example-subgroup/example-project.git",
		"https://some-user:some-token@gitlab.example.com/example-group/example-subgroup/example-project",
		"ssh://git@gitlab.example.com:2222/example-group/example-subgroup/example-project.git",
	} {
		t.Run(url, func(t *testing.T) {
			got, err := Parse(url)
			if err != nil || got != want {
				t.Errorf("Parse(%q) = %+v, %v, want %+v", url, got, err, want)
			}
		})
	}
}

// TestParseKeepsThePortOfAnHTTPSRemote asserts the host keeps the web port because the port names the GitLab endpoint.
func TestParseKeepsThePortOfAnHTTPSRemote(t *testing.T) {
	want := Remote{Host: "gitlab.example.com:8443", ProjectPath: "example-group/example-project"}
	for _, url := range []string{
		"https://gitlab.example.com:8443/example-group/example-project.git",
		"https://some-user:some-token@gitlab.example.com:8443/example-group/example-project",
	} {
		got, err := Parse(url)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %+v, %v, want %+v", url, got, err, want)
		}
	}
	if got := want.APIURL(); got != "https://gitlab.example.com:8443/api/v4" {
		t.Errorf("APIURL() = %q, want https://gitlab.example.com:8443/api/v4", got)
	}
}

func TestParseRejectsARemoteWithoutHostOrProject(t *testing.T) {
	for _, url := range []string{"", "example-project", "https://gitlab.example.com/", "git@gitlab.example.com:example-project.git", "/srv/git/example-group/example-project.git"} {
		t.Run(url, func(t *testing.T) {
			if _, err := Parse(url); !errors.Is(err, ErrUnsupportedRemote) {
				t.Errorf("Parse(%q) error = %v, want ErrUnsupportedRemote", url, err)
			}
		})
	}
}

func TestRemoteDerivesTheGitLabEndpoints(t *testing.T) {
	remote := Remote{Host: "gitlab.example.com", ProjectPath: "example-group/example-subgroup/example-project"}
	if got := remote.WebURL(); got != "https://gitlab.example.com" {
		t.Errorf("WebURL() = %q, want https://gitlab.example.com", got)
	}
	if got := remote.APIURL(); got != "https://gitlab.example.com/api/v4" {
		t.Errorf("APIURL() = %q, want https://gitlab.example.com/api/v4", got)
	}
	if got := remote.TopLevelGroup(); got != "example-group" {
		t.Errorf("TopLevelGroup() = %q, want example-group", got)
	}
}

func TestResolveReadsTheOriginOfTheRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is absent from PATH")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q"}, {"remote", "add", "origin", "git@gitlab.example.com:example-group/example-project.git"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}

	got, err := Resolve(context.Background(), dir)
	want := Remote{Host: "gitlab.example.com", ProjectPath: "example-group/example-project"}
	if err != nil || got != want {
		t.Errorf("Resolve = %+v, %v, want %+v", got, err, want)
	}
}
