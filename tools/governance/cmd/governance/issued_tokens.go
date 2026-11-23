package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/sonarusertokens"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

// vaultKV reads individual KV v2 fields and replaces the full secret payload on write.
type vaultKV struct {
	client *vaultapi.Client
}

func (v vaultKV) ReadField(ctx context.Context, f issuedtokens.VaultField) (string, error) {
	secret, err := v.client.KVv2(f.Mount).Get(ctx, f.Path)
	if err != nil {
		return "", fmt.Errorf("read %s/%s: %w", f.Mount, f.Path, err)
	}
	value, ok := secret.Data[f.Field].(string)
	if !ok || value == "" {
		return "", fmt.Errorf("%s/%s lacks the field %s", f.Mount, f.Path, f.Field)
	}
	return value, nil
}

func (v vaultKV) WriteField(ctx context.Context, f issuedtokens.VaultField, value string) error {
	if _, err := v.client.KVv2(f.Mount).Put(ctx, f.Path, map[string]any{f.Field: value}); err != nil {
		return fmt.Errorf("write %s/%s: %w", f.Mount, f.Path, err)
	}
	return nil
}

func (a *app) newAdministratorKV() (vaultKV, error) {
	cfg, err := a.buildProxyConfig(accessAdministrator)
	if err != nil {
		return vaultKV{}, err
	}
	client, err := vaultclient.NewClient(cfg)
	if err != nil {
		return vaultKV{}, err
	}
	return vaultKV{client: client}, nil
}

// newGitLabClient returns an authenticated GitLab client and the top level group ID from Vault.
func (a *app) newGitLabClient(ctx context.Context, kv vaultKV, apiURL string) (*gitlabapi.Client, string, error) {
	location, err := a.topology.ResolveStateBackendToken(a.topology.OperatorVaultProxy.GovernanceOwnerCode)
	if err != nil {
		return nil, "", err
	}
	token, err := kv.ReadField(ctx, issuedtokens.VaultField{Mount: location.Mount, Path: location.Path, Field: location.Field})
	if err != nil {
		return nil, "", err
	}
	groupID, err := kv.ReadField(ctx, a.issuedTokens.GitLabGroupRegistry)
	if err != nil {
		return nil, "", err
	}
	return gitlabapi.New(apiURL, token), groupID, nil
}

func (a *app) issueSonarQubeAnalysisToken(ctx context.Context) error {
	cfg := a.issuedTokens.SonarQubeAnalysisToken
	admin, ok := credentials.Lookup(a.credentials, cfg.AdminPasswordKey)
	if !ok {
		return fmt.Errorf("service_issued_tokens.sonarqube_analysis_token.admin_password_key names no service_admin_passwords key %q", cfg.AdminPasswordKey)
	}
	kv, err := a.newAdministratorKV()
	if err != nil {
		return err
	}
	adminPassword, err := kv.ReadField(ctx, issuedtokens.VaultField{Mount: admin.Spec.Mount, Path: admin.Spec.Path, Field: admin.Spec.Field})
	if err != nil {
		return err
	}
	origin, err := a.resolveOrigin(ctx)
	if err != nil {
		return err
	}
	gitlab, groupID, err := a.newGitLabClient(ctx, kv, origin.APIURL)
	if err != nil {
		return err
	}
	revoked, err := issuedtokens.SonarQubeAnalysisTokenRotation{
		Config:               cfg,
		GroupID:              groupID,
		Now:                  time.Now(),
		SonarQube:            sonarusertokens.New(cfg.UserTokensEndpoint, admin.AdminUsername, adminPassword),
		Vault:                kv,
		GitLabGroupVariables: gitlab,
	}.Run(ctx)
	if err != nil {
		return err
	}
	a.out.Print(ui.OK, "The SonarQube analysis token reached "+cfg.Vault.Mount+"/"+cfg.Vault.Path+" and the group variable "+cfg.GitLabGroupVariableKey+".")
	if len(revoked) > 0 {
		a.out.Print(ui.Info, "Revoked the earlier tokens: "+strings.Join(revoked, ", "))
	}
	return nil
}

func (a *app) registerGitLabGroupRunner(ctx context.Context) error {
	cfg := a.issuedTokens.GitLabGroupRunner
	kv, err := a.newAdministratorKV()
	if err != nil {
		return err
	}
	origin, err := a.resolveOrigin(ctx)
	if err != nil {
		return err
	}
	gitlab, groupID, err := a.newGitLabClient(ctx, kv, origin.APIURL)
	if err != nil {
		return err
	}
	path := filepath.Join(a.root, cfg.ConfigPath)
	id, err := issuedtokens.GroupRunnerRegistration{Config: cfg, GitLabURL: origin.WebURL, GroupID: groupID, ConfigPath: path, GitLab: gitlab}.Run(ctx)
	if err != nil {
		return err
	}
	a.out.Print(ui.OK, fmt.Sprintf("Group runner %d wrote %s. Run podman compose restart gitlab-runner to load the runner.", id, path))
	return nil
}

func (a *app) publishCodeReviewerVariables(ctx context.Context) error {
	if len(a.issuedTokens.CodeReviewerVariables.BotTokens) == 0 {
		return errors.New("service_issued_tokens.code_reviewer_variables lists no bot_tokens")
	}
	origin, err := a.resolveOrigin(ctx)
	if err != nil {
		return err
	}
	projects := a.topology.ListCodeReviewerVariableProjects(origin.TopLevelGroup)
	if len(projects) == 0 {
		return errors.New("no identity of operator_vault_proxy lists code_reviewer_variable_projects")
	}
	kv, err := a.newAdministratorKV()
	if err != nil {
		return err
	}
	gitlab, _, err := a.newGitLabClient(ctx, kv, origin.APIURL)
	if err != nil {
		return err
	}
	publication := issuedtokens.CodeReviewerVariablesPublication{Config: a.issuedTokens.CodeReviewerVariables, Projects: projects, Vault: kv, GitLab: gitlab}
	if err := publication.Run(ctx); err != nil {
		return err
	}
	a.out.Print(ui.OK, "The code reviewer variables reached "+strings.Join(projects, ", ")+".")
	return nil
}
