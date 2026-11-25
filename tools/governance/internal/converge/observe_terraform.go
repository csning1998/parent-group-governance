package converge

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/terraform"
)

const (
	// NodeTerraformFoundationVaultBastion converges the Bastion Vault trust root layer.
	NodeTerraformFoundationVaultBastion = "terraform.foundation_vault_bastion"
	// NodeTerraformGroupFoundation converges the top-level GitLab group layer.
	NodeTerraformGroupFoundation = "terraform.group_foundation"
	// NodeTerraformGroupAIProviderAnthropic converges the Anthropic AI provider federation layer.
	NodeTerraformGroupAIProviderAnthropic = "terraform.group_ai_provider_anthropic"
	// NodeTerraformGroupAIProviderGoogle converges the Google Cloud AI provider federation layer.
	NodeTerraformGroupAIProviderGoogle = "terraform.group_ai_provider_google_cloud"
	// NodeTerraformGroupAIProviderAzure converges the Azure AI provider layer.
	NodeTerraformGroupAIProviderAzure = "terraform.group_ai_provider_azure"
	// NodeTerraformAdministrationGitLab converges GitLab AI/deployment administration projects.
	NodeTerraformAdministrationGitLab = "terraform.administration_gitlab_project"
	// NodeTerraformGroupTopology converges GitLab subgroup topology declarations.
	NodeTerraformGroupTopology = "terraform.group_topology"
	// NodeTerraformGroupGitLabConfiguration converges GitLab group CI configuration.
	NodeTerraformGroupGitLabConfiguration = "terraform.group_gitlab_configuration"

	registryMount          = "registry"
	anthropicConsoleKVPath = "parent-group-governance/ai-provider-console/anthropic"
	anthropicOAuthField    = "anthropic_oauth_access_token"
)

// TerraformObserverDeps injects direnv checks, Vault probes, and direnv-scoped Terraform runners.
type TerraformObserverDeps struct {
	ProjectRoot          string
	VerifyDirenvAllowed  func(ctx context.Context, dir string) (bool, string, error)
	HasOperatorCertMount func(ctx context.Context) (bool, error)
	ReadKVMap            func(ctx context.Context, mount, path string) (map[string]string, bool, error)
	InspectLayerApplied  func(ctx context.Context, layerDir string) (bool, error)
	PlanLayer            func(ctx context.Context, req terraform.RunRequest) (terraform.PlanOutcome, error)
	ApplyLayer           func(ctx context.Context, req terraform.RunRequest) error
}

type terraformLayerSpec struct {
	id                     string
	dirName                string
	stage                  Stage
	deps                   []string
	registryPath           string
	isFoundationBastion    bool
	requiresAnthropicOAuth bool
}

var terraformLayerSpecs = []terraformLayerSpec{
	{
		id:                  NodeTerraformFoundationVaultBastion,
		dirName:             "foundation-vault-bastion",
		stage:               StageTrustRoot,
		deps:                []string{NodeVaultNetworkAllocation, NodeVaultManualTokens},
		isFoundationBastion: true,
	},
	{
		id:           NodeTerraformGroupFoundation,
		dirName:      "group-foundation",
		stage:        StageDownstream,
		deps:         []string{NodeTerraformFoundationVaultBastion},
		registryPath: "platform/gitlab-group/top-level",
	},
	{
		id:                     NodeTerraformGroupAIProviderAnthropic,
		dirName:                "group-ai-provider-anthropic",
		stage:                  StageDownstream,
		deps:                   []string{NodeTerraformFoundationVaultBastion},
		registryPath:           "platform/ai-provider/anthropic",
		requiresAnthropicOAuth: true,
	},
	{
		id:           NodeTerraformGroupAIProviderGoogle,
		dirName:      "group-ai-provider-google-cloud",
		stage:        StageDownstream,
		deps:         []string{NodeTerraformFoundationVaultBastion},
		registryPath: "platform/ai-provider/google-cloud",
	},
	{
		id:           NodeTerraformGroupAIProviderAzure,
		dirName:      "group-ai-provider-azure",
		stage:        StageDownstream,
		deps:         []string{NodeTerraformFoundationVaultBastion},
		registryPath: "platform/ai-provider/azure",
	},
	{
		id:      NodeTerraformAdministrationGitLab,
		dirName: "administration-gitlab-project",
		stage:   StageDownstream,
		deps: []string{
			NodeTerraformGroupFoundation,
			NodeTerraformGroupAIProviderAnthropic,
			NodeTerraformGroupAIProviderGoogle,
			NodeTerraformGroupAIProviderAzure,
			NodeCredentialsSonarQubeAdminPassword,
		},
		requiresAnthropicOAuth: true,
	},
	{
		id:           NodeTerraformGroupTopology,
		dirName:      "group-topology",
		stage:        StageDownstream,
		deps:         []string{NodeTerraformGroupFoundation},
		registryPath: "platform/gitlab-group/subgroups",
	},
	{
		id:      NodeTerraformGroupGitLabConfiguration,
		dirName: "group-gitlab-configuration",
		stage:   StageDownstream,
		deps:    []string{NodeTerraformGroupTopology, NodeCredentialsSonarQubeAnalysisToken},
	},
}

// BuildTerraformNodes constructs the DAG nodes covering Stage 3 and Stage 5 Terraform layers.
func BuildTerraformNodes(deps TerraformObserverDeps) []Node {
	deps = withDefaultTerraformRunners(deps)
	nodes := make([]Node, 0, len(terraformLayerSpecs))
	for _, spec := range terraformLayerSpecs {
		s := spec
		nodes = append(nodes, &funcNode{
			id:    s.id,
			stage: s.stage,
			deps:  s.deps,
			inspect: func(ctx context.Context, mode ObserveMode) (NodeReport, error) {
				return inspectTerraformLayer(ctx, deps, s, mode)
			},
			converge: func(ctx context.Context, req ConvergeContext) error {
				return convergeTerraformLayer(ctx, deps, s, req)
			},
		})
	}
	return nodes
}

func withDefaultTerraformRunners(deps TerraformObserverDeps) TerraformObserverDeps {
	if deps.VerifyDirenvAllowed == nil {
		deps.VerifyDirenvAllowed = terraform.VerifyDirenvAllowed
	}
	if deps.PlanLayer == nil {
		deps.PlanLayer = terraform.PlanLayer
	}
	if deps.ApplyLayer == nil {
		deps.ApplyLayer = terraform.ApplyLayer
	}
	return deps
}

func inspectTerraformLayer(ctx context.Context, deps TerraformObserverDeps, spec terraformLayerSpec, mode ObserveMode) (NodeReport, error) {
	layerDir := filepath.Join(deps.ProjectRoot, "terraform", "layers", spec.dirName)
	allowed, rcPath, err := deps.VerifyDirenvAllowed(ctx, layerDir)
	if err != nil {
		return NodeReport{}, err
	}
	if !allowed {
		return newDirenvBlockedReport(spec, layerDir, rcPath), nil
	}

	applied, bootstrapRoot, blockedReport, err := inspectLayerAppliedState(ctx, deps, spec, layerDir)
	if err != nil {
		return NodeReport{}, err
	}
	if blockedReport != nil {
		return *blockedReport, nil
	}

	if spec.requiresAnthropicOAuth && (mode == ObserveDeep || !applied) {
		blocked, err := inspectAnthropicOAuthGate(ctx, deps.ReadKVMap, spec)
		if err != nil || blocked != nil {
			if blocked != nil {
				return *blocked, nil
			}
			return NodeReport{}, err
		}
	}

	if mode == ObserveFast {
		return classifyFastTerraformReport(spec, applied), nil
	}
	return inspectDeepTerraformPlan(ctx, deps, spec, layerDir, applied, bootstrapRoot)
}

func newDirenvBlockedReport(spec terraformLayerSpec, layerDir, rcPath string) NodeReport {
	target := layerDir
	if rcPath != "" {
		target = rcPath
	}
	return NodeReport{
		ID:      spec.id,
		Stage:   spec.stage,
		State:   StateBlocked,
		Summary: "direnv approval required",
		Hint:    "run direnv allow " + target,
	}
}

func inspectLayerAppliedState(
	ctx context.Context,
	deps TerraformObserverDeps,
	spec terraformLayerSpec,
	layerDir string,
) (applied, bootstrapRoot bool, blocked *NodeReport, err error) {
	if spec.isFoundationBastion {
		if deps.HasOperatorCertMount == nil {
			rep := NodeReport{ID: spec.id, Stage: spec.stage, State: StateBlocked, Summary: "operator-cert probe not configured"}
			return false, false, &rep, nil
		}
		mounted, err := deps.HasOperatorCertMount(ctx)
		if err != nil {
			return false, false, nil, err
		}
		return mounted, !mounted, nil, nil
	}
	if spec.registryPath != "" && deps.ReadKVMap != nil {
		_, found, err := deps.ReadKVMap(ctx, registryMount, spec.registryPath)
		return found, false, nil, err
	}
	if deps.InspectLayerApplied != nil {
		ok, err := deps.InspectLayerApplied(ctx, layerDir)
		return ok, false, nil, err
	}
	return false, false, nil, nil
}

func inspectAnthropicOAuthGate(
	ctx context.Context,
	readKV func(context.Context, string, string) (map[string]string, bool, error),
	spec terraformLayerSpec,
) (*NodeReport, error) {
	hasOAuth, err := hasAnthropicOAuthToken(ctx, readKV)
	if err != nil {
		return nil, err
	}
	if hasOAuth {
		return nil, nil
	}
	return &NodeReport{
		ID:      spec.id,
		Stage:   spec.stage,
		State:   StateBlocked,
		Summary: "Anthropic OAuth access token missing in Vault",
		Hint:    "run ant auth login and write anthropic_oauth_access_token to Vault",
	}, nil
}

func hasAnthropicOAuthToken(
	ctx context.Context,
	readKV func(context.Context, string, string) (map[string]string, bool, error),
) (bool, error) {
	if readKV == nil {
		return false, nil
	}
	data, found, err := readKV(ctx, secretMount, anthropicConsoleKVPath)
	if err != nil {
		return false, err
	}
	return found && data[anthropicOAuthField] != "", nil
}

func classifyFastTerraformReport(spec terraformLayerSpec, applied bool) NodeReport {
	if applied {
		return NodeReport{ID: spec.id, Stage: spec.stage, State: StateConverged, Summary: spec.dirName + " converged"}
	}
	return NodeReport{ID: spec.id, Stage: spec.stage, State: StateAbsent, Summary: spec.dirName + " not applied"}
}

func inspectDeepTerraformPlan(
	ctx context.Context,
	deps TerraformObserverDeps,
	spec terraformLayerSpec,
	layerDir string,
	applied, bootstrapRoot bool,
) (NodeReport, error) {
	outcome, err := deps.PlanLayer(ctx, terraform.RunRequest{
		LayerDir:              layerDir,
		BootstrapRootIdentity: bootstrapRoot,
	})
	if err != nil {
		return NodeReport{}, err
	}
	switch outcome {
	case terraform.PlanConverged:
		return NodeReport{ID: spec.id, Stage: spec.stage, State: StateConverged, Summary: spec.dirName + " plan reports no changes"}, nil
	case terraform.PlanDrifted:
		if !applied {
			return NodeReport{ID: spec.id, Stage: spec.stage, State: StateAbsent, Summary: spec.dirName + " pending initial apply"}, nil
		}
		return NodeReport{ID: spec.id, Stage: spec.stage, State: StateDrifted, Summary: spec.dirName + " plan detected drift"}, nil
	default:
		return NodeReport{}, fmt.Errorf("converge: unexpected plan outcome %q for %s", outcome, spec.id)
	}
}

func convergeTerraformLayer(ctx context.Context, deps TerraformObserverDeps, spec terraformLayerSpec, req ConvergeContext) error {
	layerDir := filepath.Join(deps.ProjectRoot, "terraform", "layers", spec.dirName)
	bootstrapRoot := false
	if spec.isFoundationBastion {
		if deps.HasOperatorCertMount == nil {
			return errors.New("converge: HasOperatorCertMount handler not configured")
		}
		mounted, err := deps.HasOperatorCertMount(ctx)
		if err != nil {
			return err
		}
		bootstrapRoot = !mounted
	}
	if spec.requiresAnthropicOAuth {
		hasOAuth, err := hasAnthropicOAuthToken(ctx, deps.ReadKVMap)
		if err != nil {
			return err
		}
		if !hasOAuth {
			return errors.New("converge: anthropic_oauth_access_token missing in Vault; run ant auth login")
		}
	}
	return deps.ApplyLayer(ctx, terraform.RunRequest{
		LayerDir:              layerDir,
		BootstrapRootIdentity: bootstrapRoot,
		AutoApprove:           req.AutoApprove,
		Stdin:                 req.Stdin,
		Stdout:                req.Stdout,
		Stderr:                req.Stderr,
	})
}
