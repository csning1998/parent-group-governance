package issuedtokens

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
)

// fakeSecretReader returns a fixed value per Vault field and counts the reads.
type fakeSecretReader struct {
	values map[VaultField]string
	err    error
	reads  int
}

func (f *fakeSecretReader) ReadField(_ context.Context, field VaultField) (string, error) {
	f.reads++
	if f.err != nil {
		return "", f.err
	}
	return f.values[field], nil
}

// fakeProjectVariables answers the presence of each project and records every variable write.
type fakeProjectVariables struct {
	present map[string]bool
	writes  []string
}

func (f *fakeProjectVariables) HasProject(_ context.Context, projectPath string) (bool, error) {
	return f.present[projectPath], nil
}

func (f *fakeProjectVariables) UpsertProjectVariable(_ context.Context, projectPath string, v gitlabapi.Variable) error {
	if !v.Masked || !v.Hidden || !v.Raw || v.Protected {
		return errors.New("unexpected flags on " + v.Key)
	}
	f.writes = append(f.writes, projectPath+" "+v.Key+"="+v.Value)
	return nil
}

var (
	reviewerBotField = VaultField{Mount: "secret", Path: "gitlab-ci-with-code-reviewer/integration/code-reviewer-bot", Field: "token"}
	tagBotField      = VaultField{Mount: "secret", Path: "gitlab-ci-with-code-reviewer/integration/auto-version-tag-bot", Field: "token"}
	reviewerConfig   = CodeReviewerVariablesConfig{BotTokens: []ReviewerBotToken{
		{Vault: reviewerBotField, VariableKeys: []string{"REVIEW_MR_REVIEWER", "CLAUDE_MR_REVIEWER", "GEMINI_MR_REVIEWER"}},
		{Vault: tagBotField, VariableKeys: []string{"TAG_PUSH_TOKEN"}},
	}}
)

// TestCodeReviewerVariablesPublicationRun asserts the writes into every listed project and the refusal before any write.
func TestCodeReviewerVariablesPublicationRun(t *testing.T) {
	cases := map[string]struct {
		projects    []string
		vaultErr    error
		wantErr     error
		wantMissing []string
		wantReads   int
		wantWrites  []string
	}{
		"every listed project receives every variable": {
			projects:  []string{"csning1998-lab/parent-group-governance", "csning1998-lab/gitlab-ci-with-code-reviewer"},
			wantReads: 2,
			wantWrites: []string{
				"csning1998-lab/parent-group-governance REVIEW_MR_REVIEWER=reviewer-token",
				"csning1998-lab/parent-group-governance CLAUDE_MR_REVIEWER=reviewer-token",
				"csning1998-lab/parent-group-governance GEMINI_MR_REVIEWER=reviewer-token",
				"csning1998-lab/parent-group-governance TAG_PUSH_TOKEN=tag-token",
				"csning1998-lab/gitlab-ci-with-code-reviewer REVIEW_MR_REVIEWER=reviewer-token",
				"csning1998-lab/gitlab-ci-with-code-reviewer CLAUDE_MR_REVIEWER=reviewer-token",
				"csning1998-lab/gitlab-ci-with-code-reviewer GEMINI_MR_REVIEWER=reviewer-token",
				"csning1998-lab/gitlab-ci-with-code-reviewer TAG_PUSH_TOKEN=tag-token",
			},
		},
		"absent projects stop the publication before any read or write": {
			projects:    []string{"csning1998-lab/parent-group-governance", "personal/absent-one", "personal/absent-two"},
			wantErr:     ErrMissingProjects,
			wantMissing: []string{"personal/absent-one", "personal/absent-two"},
		},
		"a failed Vault read writes nothing": {
			projects:  []string{"csning1998-lab/parent-group-governance"},
			vaultErr:  errors.New("permission denied"),
			wantErr:   errors.New("permission denied"),
			wantReads: 1,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			vault := &fakeSecretReader{values: map[VaultField]string{reviewerBotField: "reviewer-token", tagBotField: "tag-token"}, err: tc.vaultErr}
			gitlab := &fakeProjectVariables{present: map[string]bool{
				"csning1998-lab/parent-group-governance":      true,
				"csning1998-lab/gitlab-ci-with-code-reviewer": true,
			}}

			err := CodeReviewerVariablesPublication{Config: reviewerConfig, Projects: tc.projects, Vault: vault, GitLab: gitlab}.Run(context.Background())
			switch {
			case tc.wantErr == nil && err != nil:
				t.Fatal(err)
			case tc.wantErr != nil && (err == nil || !errors.Is(err, tc.wantErr) && !strings.Contains(err.Error(), tc.wantErr.Error())):
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			for _, path := range tc.wantMissing {
				if !strings.Contains(err.Error(), path) {
					t.Fatalf("the error %v lacks %s", err, path)
				}
			}
			if vault.reads != tc.wantReads || !slices.Equal(gitlab.writes, tc.wantWrites) {
				t.Fatalf("got %d reads and writes %v, want %d reads and writes %v", vault.reads, gitlab.writes, tc.wantReads, tc.wantWrites)
			}
		})
	}
}
