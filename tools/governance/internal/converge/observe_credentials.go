package converge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

const (
	// NodeCredentialsSonarQubeAdminPassword converges Bastion Vault and live SonarQube admin password state.
	NodeCredentialsSonarQubeAdminPassword = "credentials.sonarqube_admin_password"
	// NodeCredentialsGitLabGroupRunner converges the registered GitLab group runner and its config.toml.
	NodeCredentialsGitLabGroupRunner = "credentials.gitlab_group_runner"
	// NodeCredentialsSonarQubeAnalysisToken converges the SonarQube CI analysis token and group SONAR_TOKEN.
	NodeCredentialsSonarQubeAnalysisToken = "credentials.sonarqube_analysis_token"
	// NodeCredentialsCodeReviewerVariables converges code-reviewer bot variables across listed projects.
	NodeCredentialsCodeReviewerVariables = "credentials.code_reviewer_variables"

	sonarAdminKVPath        = "parent-group-governance/sonarqube/admin-account"
	sonarAdminKVField       = "sonarqube_admin_password"
	sonarAnalysisKVPath     = "parent-group-governance/sonarqube/ci-analysis-bot"
	sonarAnalysisKVField    = "sonarqube_ci_token"
	sonarTokenGroupVarKey   = "SONAR_TOKEN"
	defaultRunnerConfigPath = "gitlab-runner-configs/config.toml"
)

// CredentialObserverDeps injects Vault/service probes and credential issuance callbacks.
type CredentialObserverDeps struct {
	ProjectRoot                  string
	RunnerConfigPath             string
	ReadKVMap                    func(ctx context.Context, mount, path string) (map[string]string, bool, error)
	VerifySonarQubeAdmin         func(ctx context.Context) (bool, error)
	VerifyGroupVariable          func(ctx context.Context, key string) (bool, error)
	VerifyProjectVariables       func(ctx context.Context) (present, total int, err error)
	RotateSonarQubeAdmin         func(ctx context.Context, req ConvergeContext) error
	RegisterGitLabGroupRunner    func(ctx context.Context, req ConvergeContext) error
	IssueSonarQubeAnalysisToken  func(ctx context.Context, req ConvergeContext) error
	PublishCodeReviewerVariables func(ctx context.Context, req ConvergeContext) error
}

// WorkstationDeps aggregates dependencies for all host, Vault, Terraform, and credential DAG nodes.
type WorkstationDeps struct {
	Host        HostObserverDeps
	Vault       VaultObserverDeps
	Terraform   TerraformObserverDeps
	Credentials CredentialObserverDeps
}

// DefaultRootHygieneDeps returns the terminal Stage 5 node IDs required before revoking the bootstrap root token.
func DefaultRootHygieneDeps() []string {
	return []string{
		NodeTerraformGroupGitLabConfiguration,
		NodeCredentialsGitLabGroupRunner,
		NodeCredentialsCodeReviewerVariables,
	}
}

// BuildCredentialNodes constructs the DAG nodes covering Stage 4 admin password rotation and Stage 5 issued tokens.
func BuildCredentialNodes(deps CredentialObserverDeps) []Node {
	return []Node{
		&funcNode{
			id:    NodeCredentialsSonarQubeAdminPassword,
			stage: StageBastionObservability,
			deps:  []string{NodeTerraformFoundationVaultBastion},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectSonarAdminPassword(ctx, deps)
			},
			converge: callConvergeAction(NodeCredentialsSonarQubeAdminPassword, deps.RotateSonarQubeAdmin),
		},
		&funcNode{
			id:    NodeCredentialsGitLabGroupRunner,
			stage: StageDownstream,
			deps:  []string{NodeTerraformAdministrationGitLab, NodeHostTelemetry},
			inspect: func(context.Context, ObserveMode) (NodeReport, error) {
				return inspectGitLabGroupRunner(deps)
			},
			converge: callConvergeAction(NodeCredentialsGitLabGroupRunner, deps.RegisterGitLabGroupRunner),
		},
		&funcNode{
			id:    NodeCredentialsSonarQubeAnalysisToken,
			stage: StageDownstream,
			deps:  []string{NodeCredentialsSonarQubeAdminPassword, NodeTerraformGroupTopology},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectSonarQubeAnalysisToken(ctx, deps)
			},
			converge: callConvergeAction(NodeCredentialsSonarQubeAnalysisToken, deps.IssueSonarQubeAnalysisToken),
		},
		&funcNode{
			id:    NodeCredentialsCodeReviewerVariables,
			stage: StageDownstream,
			deps:  []string{NodeTerraformAdministrationGitLab},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectCodeReviewerVariables(ctx, deps)
			},
			converge: callConvergeAction(NodeCredentialsCodeReviewerVariables, deps.PublishCodeReviewerVariables),
		},
	}
}

// BuildWorkstationGraph assembles and validates the complete Stage 0..5 workstation convergence DAG.
func BuildWorkstationGraph(deps WorkstationDeps) (*Graph, error) {
	vaultDeps := deps.Vault
	if len(vaultDeps.RootHygieneDeps) == 0 {
		vaultDeps.RootHygieneDeps = DefaultRootHygieneDeps()
	}

	var nodes []Node
	nodes = append(nodes, BuildHostNodes(deps.Host)...)
	nodes = append(nodes, BuildVaultNodes(vaultDeps)...)
	nodes = append(nodes, BuildTerraformNodes(deps.Terraform)...)
	nodes = append(nodes, BuildCredentialNodes(deps.Credentials)...)
	return NewGraph(nodes...)
}

func inspectSonarAdminPassword(ctx context.Context, deps CredentialObserverDeps) (NodeReport, error) {
	if deps.ReadKVMap == nil {
		return NodeReport{ID: NodeCredentialsSonarQubeAdminPassword, Stage: StageBastionObservability, State: StateBlocked, Summary: "KV reader not configured"}, nil
	}
	data, found, err := deps.ReadKVMap(ctx, secretMount, sonarAdminKVPath)
	if err != nil {
		return NodeReport{}, err
	}
	if !found || data[sonarAdminKVField] == "" {
		return NodeReport{ID: NodeCredentialsSonarQubeAdminPassword, Stage: StageBastionObservability, State: StateAbsent, Summary: "SonarQube admin password not rotated yet"}, nil
	}
	if deps.VerifySonarQubeAdmin != nil {
		ok, err := deps.VerifySonarQubeAdmin(ctx)
		if err != nil {
			return NodeReport{}, err
		}
		if !ok {
			return NodeReport{ID: NodeCredentialsSonarQubeAdminPassword, Stage: StageBastionObservability, State: StateDrifted, Summary: "live SonarQube admin password differs from Vault"}, nil
		}
	}
	return NodeReport{ID: NodeCredentialsSonarQubeAdminPassword, Stage: StageBastionObservability, State: StateConverged, Summary: "SonarQube admin password synchronized"}, nil
}

func inspectGitLabGroupRunner(deps CredentialObserverDeps) (NodeReport, error) {
	relPath := deps.RunnerConfigPath
	if relPath == "" {
		relPath = defaultRunnerConfigPath
	}
	fullPath := filepath.Join(deps.ProjectRoot, relPath)
	raw, err := os.ReadFile(fullPath)
	if errors.Is(err, fs.ErrNotExist) {
		return NodeReport{ID: NodeCredentialsGitLabGroupRunner, Stage: StageDownstream, State: StateAbsent, Summary: "GitLab runner config.toml absent"}, nil
	}
	if err != nil {
		return NodeReport{}, fmt.Errorf("converge: read %s: %w", fullPath, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return NodeReport{ID: NodeCredentialsGitLabGroupRunner, Stage: StageDownstream, State: StateDrifted, Summary: "GitLab runner config.toml is empty"}, nil
	}
	return NodeReport{ID: NodeCredentialsGitLabGroupRunner, Stage: StageDownstream, State: StateConverged, Summary: "GitLab runner config.toml present"}, nil
}

func inspectSonarQubeAnalysisToken(ctx context.Context, deps CredentialObserverDeps) (NodeReport, error) {
	if deps.ReadKVMap == nil {
		return NodeReport{ID: NodeCredentialsSonarQubeAnalysisToken, Stage: StageDownstream, State: StateBlocked, Summary: "KV reader not configured"}, nil
	}
	data, found, err := deps.ReadKVMap(ctx, secretMount, sonarAnalysisKVPath)
	if err != nil {
		return NodeReport{}, err
	}
	if !found || data[sonarAnalysisKVField] == "" {
		return NodeReport{ID: NodeCredentialsSonarQubeAnalysisToken, Stage: StageDownstream, State: StateAbsent, Summary: "SonarQube analysis token not issued yet"}, nil
	}
	if deps.VerifyGroupVariable != nil {
		ok, err := deps.VerifyGroupVariable(ctx, sonarTokenGroupVarKey)
		if err != nil {
			return NodeReport{}, err
		}
		if !ok {
			return NodeReport{ID: NodeCredentialsSonarQubeAnalysisToken, Stage: StageDownstream, State: StateDrifted, Summary: "GitLab group SONAR_TOKEN missing or out of sync"}, nil
		}
	}
	return NodeReport{ID: NodeCredentialsSonarQubeAnalysisToken, Stage: StageDownstream, State: StateConverged, Summary: "SonarQube analysis token synchronized"}, nil
}

func inspectCodeReviewerVariables(ctx context.Context, deps CredentialObserverDeps) (NodeReport, error) {
	if deps.VerifyProjectVariables == nil {
		return NodeReport{ID: NodeCredentialsCodeReviewerVariables, Stage: StageDownstream, State: StateBlocked, Summary: "project variable verifier not configured"}, nil
	}
	present, total, err := deps.VerifyProjectVariables(ctx)
	if err != nil {
		return NodeReport{}, err
	}
	if total == 0 || present == total {
		return NodeReport{ID: NodeCredentialsCodeReviewerVariables, Stage: StageDownstream, State: StateConverged, Summary: fmt.Sprintf("all %d code-reviewer project variables present", present)}, nil
	}
	if present == 0 {
		return NodeReport{ID: NodeCredentialsCodeReviewerVariables, Stage: StageDownstream, State: StateAbsent, Summary: "code-reviewer project variables not published yet"}, nil
	}
	return NodeReport{ID: NodeCredentialsCodeReviewerVariables, Stage: StageDownstream, State: StateDrifted, Summary: fmt.Sprintf("%d/%d code-reviewer project variables present", present, total)}, nil
}
