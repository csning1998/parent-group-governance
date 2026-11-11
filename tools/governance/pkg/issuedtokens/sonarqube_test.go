package issuedtokens

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/sonarusertokens"
)

// fakeSonarQube records generated and revoked SonarQube user tokens for test verification.
type fakeSonarQube struct {
	tokens  []sonarusertokens.Token
	revoked []string
}

func (f *fakeSonarQube) Generate(_ context.Context, name, tokenType string) (string, error) {
	f.tokens = append(f.tokens, sonarusertokens.Token{Name: name, Type: tokenType})
	return "value-of-" + name, nil
}

func (f *fakeSonarQube) List(context.Context) ([]sonarusertokens.Token, error) {
	return slices.Clone(f.tokens), nil
}

func (f *fakeSonarQube) Revoke(_ context.Context, name string) error {
	f.revoked = append(f.revoked, name)
	return nil
}

// fakeVault records secret field writes and simulates storage failure scenarios.
type fakeVault struct {
	written map[VaultField]string
	err     error
}

func (f *fakeVault) WriteField(_ context.Context, field VaultField, value string) error {
	if f.err != nil {
		return f.err
	}
	f.written[field] = value
	return nil
}

// fakeGitLab records group variable mutations and simulates GitLab API failure scenarios.
type fakeGitLab struct {
	groupID  string
	variable gitlabapi.Variable
	err      error
}

func (f *fakeGitLab) UpsertGroupVariable(_ context.Context, groupID string, v gitlabapi.Variable) error {
	if f.err != nil {
		return f.err
	}
	f.groupID, f.variable = groupID, v
	return nil
}

var analysisTokenConfig = SonarQubeAnalysisTokenConfig{
	TokenNamePrefix:        "gitlab-ci-analysis",
	Vault:                  VaultField{Mount: "secret", Path: "parent-group-governance/sonarqube/ci-analysis-bot", Field: "sonarqube_ci_token"},
	GitLabGroupVariableKey: "SONAR_TOKEN",
}

const issuedName = "gitlab-ci-analysis-20261111T093000Z"

// newRotation constructs a SonarQubeAnalysisTokenRotation instance configured with deterministic test fixtures.
func newRotation(sonar *fakeSonarQube, vault *fakeVault, gitlab *fakeGitLab) SonarQubeAnalysisTokenRotation {
	return SonarQubeAnalysisTokenRotation{
		Config:               analysisTokenConfig,
		GroupID:              "42",
		Now:                  time.Date(2026, 11, 11, 17, 30, 0, 0, time.FixedZone("UTC+8", 8*3600)),
		SonarQube:            sonar,
		Vault:                vault,
		GitLabGroupVariables: gitlab,
	}
}

// TestSonarQubeAnalysisTokenRotationRun asserts Vault storage, group variable updates, and token revocation across successful and failed rotation attempts.
func TestSonarQubeAnalysisTokenRotationRun(t *testing.T) {
	newValue := "value-of-" + issuedName
	cases := map[string]struct {
		vaultErr     error
		gitlabErr    error
		wantErr      bool
		wantVault    string
		wantVariable gitlabapi.Variable
		wantRevoked  []string
	}{
		"a rotation revokes the bare prefix and the earlier timestamped token": {
			wantVault:    newValue,
			wantVariable: gitlabapi.Variable{Key: "SONAR_TOKEN", Value: newValue, Masked: true, Hidden: true, Raw: true},
			wantRevoked:  []string{"gitlab-ci-analysis", "gitlab-ci-analysis-20261001T000000Z"},
		},
		"a failed Vault write revokes the new token alone": {
			vaultErr:    errors.New("permission denied"),
			wantErr:     true,
			wantRevoked: []string{issuedName},
		},
		"a failed group variable write keeps every earlier token": {
			gitlabErr: errors.New("403 Forbidden"),
			wantErr:   true,
			wantVault: newValue,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sonar := &fakeSonarQube{tokens: []sonarusertokens.Token{
				{Name: "gitlab-ci-analysis", Type: globalAnalysisTokenType},
				{Name: "gitlab-ci-analysis-20261001T000000Z", Type: globalAnalysisTokenType},
				{Name: "gitlab-ci-analysis-ide", Type: "USER_TOKEN"},
				{Name: "gitlab-ci-analysisx", Type: globalAnalysisTokenType},
			}}
			vault := &fakeVault{written: map[VaultField]string{}, err: tc.vaultErr}
			gitlab := &fakeGitLab{err: tc.gitlabErr}

			_, err := newRotation(sonar, vault, gitlab).Run(context.Background())
			if (err != nil) != tc.wantErr {
				t.Fatalf("got error %v, want an error %t", err, tc.wantErr)
			}
			if got := vault.written[analysisTokenConfig.Vault]; got != tc.wantVault {
				t.Fatalf("the Bastion Vault holds %q, want %q", got, tc.wantVault)
			}
			if gitlab.variable != tc.wantVariable {
				t.Fatalf("the group variable is %+v, want %+v", gitlab.variable, tc.wantVariable)
			}
			if !slices.Equal(sonar.revoked, tc.wantRevoked) {
				t.Fatalf("revoked %v, want %v", sonar.revoked, tc.wantRevoked)
			}
		})
	}
}
