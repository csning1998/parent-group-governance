package issuedtokens

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/sonarusertokens"
)

const globalAnalysisTokenType = "GLOBAL_ANALYSIS_TOKEN"

// AnalysisTokenService defines lifecycle operations for SonarQube user analysis tokens.
type AnalysisTokenService interface {
	Generate(ctx context.Context, name, tokenType string) (string, error)
	List(ctx context.Context) ([]sonarusertokens.Token, error)
	Revoke(ctx context.Context, name string) error
}

// SecretWriter overwrites the target Vault KV v2 secret path with a single field.
type SecretWriter interface {
	WriteField(ctx context.Context, field VaultField, value string) error
}

// GroupVariableWriter manages CI/CD variables on GitLab groups.
type GroupVariableWriter interface {
	UpsertGroupVariable(ctx context.Context, groupID string, v gitlabapi.Variable) error
}

// SonarQubeAnalysisTokenRotation writes a new analysis token to Vault and GitLab before revoking prior tokens to keep CI uninterrupted.
type SonarQubeAnalysisTokenRotation struct {
	Config               SonarQubeAnalysisTokenConfig
	GroupID              string
	Now                  time.Time
	SonarQube            AnalysisTokenService
	Vault                SecretWriter
	GitLabGroupVariables GroupVariableWriter
}

// Run executes analysis token rotation and returns the names of revoked prior tokens.
func (r SonarQubeAnalysisTokenRotation) Run(ctx context.Context) ([]string, error) {
	name := r.Config.TokenNamePrefix + "-" + r.Now.UTC().Format("20060102T150405Z")
	token, err := r.SonarQube.Generate(ctx, name, globalAnalysisTokenType)
	if err != nil {
		return nil, err
	}
	if err := r.Vault.WriteField(ctx, r.Config.Vault, token); err != nil {
		return nil, errors.Join(fmt.Errorf("issuedtokens: write %s into %s/%s: %w", name, r.Config.Vault.Mount, r.Config.Vault.Path, err), r.SonarQube.Revoke(ctx, name))
	}
	variable := gitlabapi.Variable{Key: r.Config.GitLabGroupVariableKey, Value: token, Masked: true, Hidden: true, Raw: true}
	if err := r.GitLabGroupVariables.UpsertGroupVariable(ctx, r.GroupID, variable); err != nil {
		return nil, fmt.Errorf("issuedtokens: the Bastion Vault stores %s while the group variable %s retains the earlier token, rerun to converge: %w", name, variable.Key, err)
	}
	return r.revokeEarlierTokens(ctx, name)
}

// revokeEarlierTokens matches both the bare prefix and hyphenated timestamps because group-sonarqube named the initial token with only the bare prefix.
func (r SonarQubeAnalysisTokenRotation) revokeEarlierTokens(ctx context.Context, current string) ([]string, error) {
	tokens, err := r.SonarQube.List(ctx)
	if err != nil {
		return nil, err
	}
	prefix := r.Config.TokenNamePrefix
	var revoked []string
	for _, t := range tokens {
		issuedByPrefix := t.Name == prefix || strings.HasPrefix(t.Name, prefix+"-")
		if t.Type != globalAnalysisTokenType || !issuedByPrefix || t.Name == current {
			continue
		}
		if err := r.SonarQube.Revoke(ctx, t.Name); err != nil {
			return revoked, err
		}
		revoked = append(revoked, t.Name)
	}
	return revoked, nil
}
