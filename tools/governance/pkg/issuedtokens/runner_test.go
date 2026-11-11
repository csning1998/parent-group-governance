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
	Description: "parent-group-governance-shared-podman-runner",
	TagList:     []string{"podman", "local", "sonarqube-network"},
	GitLabURL:   "https://gitlab.com",
	ConfigPath:  "gitlab-runner-configs/config.toml",
}

// TestGroupRunnerRegistrationRun asserts the written config.toml, the refusal of an existing file, and both failure paths.
func TestGroupRunnerRegistrationRun(t *testing.T) {
	cases := map[string]struct {
		prepare      func(t *testing.T, path string)
		createErr    error
		wantErr      error
		wantRequests int
		wantFile     bool
		wantRunnerID int
	}{
		"a registration writes the token into a 0600 config.toml": {
			wantRequests: 1,
			wantFile:     true,
			wantRunnerID: 9171,
		},
		"an existing config.toml refuses the registration": {
			prepare: func(t *testing.T, path string) {
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("earlier"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr:  ErrRunnerConfigExists,
			wantFile: true,
		},
		"a failed creation writes no file": {
			createErr:    errors.New("403 Forbidden"),
			wantErr:      errors.New("403 Forbidden"),
			wantRequests: 1,
		},
		"a failed write reports the created runner": {
			prepare: func(t *testing.T, path string) {
				if os.Geteuid() == 0 {
					t.Skip("skipping permission-bit test when running as root")
				}
				dir := filepath.Dir(path)
				if err := os.MkdirAll(dir, 0o500); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			},
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

			id, err := GroupRunnerRegistration{Config: groupRunnerConfig, GroupID: "137791469", ConfigPath: path, GitLab: creator}.Run(context.Background())
			assertRunnerError(t, err, tc.wantErr)
			if id != tc.wantRunnerID || len(creator.requested) != tc.wantRequests {
				t.Fatalf("got runner %d after %d requests, want runner %d after %d requests", id, len(creator.requested), tc.wantRunnerID, tc.wantRequests)
			}
			if tc.wantRequests > 0 {
				got := creator.requested[0]
				if got.GroupID != "137791469" || !got.Locked || !got.RunUntagged || strings.Join(got.TagList, ",") != "podman,local,sonarqube-network" {
					t.Fatalf("requested %+v", got)
				}
			}
			_, statErr := os.Stat(path)
			if (statErr == nil) != tc.wantFile {
				t.Fatalf("config.toml exists %t, want %t", statErr == nil, tc.wantFile)
			}
			if tc.wantFile && tc.wantErr == nil {
				assertRunnerConfig(t, path)
			}
		})
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
		`name         = "parent-group-governance-shared-podman-runner"`,
		`url          = "https://gitlab.com"`,
		`token        = "glrt-issued"`,
	} {
		if !strings.Contains(string(content), line) {
			t.Fatalf("config.toml lacks %s", line)
		}
	}
}
