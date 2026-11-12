package issuedtokens

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
)

// fakeRunnerCreator records the requested runner and returns a fixed runner or a failure.
type fakeRunnerCreator struct {
	requested []gitlabapi.GroupRunner
	err       error
}

func (f *fakeRunnerCreator) CreateGroupRunner(_ context.Context, r gitlabapi.GroupRunner) (gitlabapi.CreatedRunner, error) {
	f.requested = append(f.requested, r)
	if f.err != nil {
		return gitlabapi.CreatedRunner{}, f.err
	}
	return gitlabapi.CreatedRunner{ID: 9171, Token: "glrt-issued"}, nil
}

var groupRunnerConfig = GitLabGroupRunnerConfig{
	Description: "example-governance-shared-podman-runner",
	TagList:     []string{"podman", "local", "sonarqube-network"},
	ConfigPath:  "gitlab-runner-configs/config.toml",
}

const exampleGitLabURL = "https://gitlab.example.com"

// TestGroupRunnerRegistrationRun asserts the written config.toml, the refusal of an existing file, and both failure paths.
func TestGroupRunnerRegistrationRun(t *testing.T) {
	cases := map[string]runnerRegistrationCase{
		"a registration writes the token into a 0600 config.toml": {
			wantRequests: 1,
			wantFile:     true,
			wantRunnerID: 9171,
		},
		"an existing config.toml refuses the registration": {
			prepare:  writeEarlierRunnerConfig,
			wantErr:  ErrRunnerConfigExists,
			wantFile: true,
		},
		"a failed creation writes no file": {
			createErr:    errors.New("403 Forbidden"),
			wantErr:      errors.New("403 Forbidden"),
			wantRequests: 1,
		},
		"a failed write reports the created runner": {
			prepare:      lockRunnerConfigDir,
			wantErr:      errors.New("runner 9171 exists in GitLab"),
			wantRequests: 1,
			wantRunnerID: 9171,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), groupRunnerConfig.ConfigPath)
			if tc.prepare != nil {
				tc.prepare(t, path)
			}
			creator := &fakeRunnerCreator{err: tc.createErr}

			id, err := GroupRunnerRegistration{Config: groupRunnerConfig, GitLabURL: exampleGitLabURL, GroupID: "1001", ConfigPath: path, GitLab: creator}.Run(context.Background())
			assertRunnerRegistration(t, tc, path, id, err, creator)
		})
	}
}

// runnerRegistrationCase declares one registration scenario and the expected outcome.
type runnerRegistrationCase struct {
	prepare      func(t *testing.T, path string)
	createErr    error
	wantErr      error
	wantRequests int
	wantFile     bool
	wantRunnerID int
}

func writeEarlierRunnerConfig(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("earlier"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lockRunnerConfigDir(t *testing.T, path string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("skipping permission-bit test when running as root")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
}

func assertRunnerRegistration(t *testing.T, tc runnerRegistrationCase, path string, id int, err error, creator *fakeRunnerCreator) {
	t.Helper()
	assertRunnerError(t, err, tc.wantErr)
	if id != tc.wantRunnerID || len(creator.requested) != tc.wantRequests {
		t.Fatalf("got runner %d after %d requests, want runner %d after %d requests", id, len(creator.requested), tc.wantRunnerID, tc.wantRequests)
	}
	if tc.wantRequests > 0 {
		assertRequestedRunner(t, creator.requested[0])
	}
	_, statErr := os.Stat(path)
	if (statErr == nil) != tc.wantFile {
		t.Fatalf("config.toml exists %t, want %t", statErr == nil, tc.wantFile)
	}
	if tc.wantFile && tc.wantErr == nil {
		assertRunnerConfig(t, path)
	}
}

func assertRequestedRunner(t *testing.T, got gitlabapi.GroupRunner) {
	t.Helper()
	if got.GroupID != "1001" || !got.Locked || !got.RunUntagged || strings.Join(got.TagList, ",") != "podman,local,sonarqube-network" {
		t.Fatalf("requested %+v", got)
	}
}

func assertRunnerError(t *testing.T, err, want error) {
	t.Helper()
	switch {
	case want == nil && err != nil:
		t.Fatal(err)
	case want != nil && err == nil:
		t.Fatalf("got no error, want %v", want)
	case want != nil && !errors.Is(err, want) && !strings.Contains(err.Error(), want.Error()):
		t.Fatalf("got %v, want %v", err, want)
	}
}

func assertRunnerConfig(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config.toml carries mode %o, want 600", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		`name         = "example-governance-shared-podman-runner"`,
		`url          = "` + exampleGitLabURL + `"`,
		`token        = "glrt-issued"`,
	} {
		if !strings.Contains(string(content), line) {
			t.Fatalf("config.toml lacks %s", line)
		}
	}
}

// TestWriteRunnerConfig asserts the refusal of a config.toml created after the existence check of Run.
func TestWriteRunnerConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), groupRunnerConfig.ConfigPath)
	writeEarlierRunnerConfig(t, path)

	err := writeRunnerConfig(path, groupRunnerConfig, exampleGitLabURL, "glrt-issued")
	if !errors.Is(err, ErrRunnerConfigExists) {
		t.Fatalf("got %v, want %v", err, ErrRunnerConfigExists)
	}
	content, readErr := os.ReadFile(path)
	if readErr != nil || string(content) != "earlier" {
		t.Fatalf("config.toml holds %q, %v, want the earlier content", content, readErr)
	}
}
