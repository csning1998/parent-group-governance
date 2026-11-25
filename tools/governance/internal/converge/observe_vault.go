package converge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

const (
	// NodeVaultInitialized inspects Bastion Vault initialization and factory-default guard.
	NodeVaultInitialized = "vault.initialized"
	// NodeVaultUnsealed inspects Bastion Vault seal status and stored unseal keys.
	NodeVaultUnsealed = "vault.unsealed"
	// NodeVaultKVSecret inspects whether the secret/ KV v2 engine is mounted.
	NodeVaultKVSecret = "vault.kv_secret"
	// NodeVaultNetworkAllocation inspects and converges non-sensitive network allocation facts in Vault.
	NodeVaultNetworkAllocation = "vault.network_allocation"
	// NodeVaultManualTokens gates downstream layers on manually populated external/GitLab tokens.
	NodeVaultManualTokens = "vault.manual_tokens"
	// NodeVaultRootHygiene verifies that administrator proxy is active and ~/.vault-token is revoked.
	NodeVaultRootHygiene = "vault.root_hygiene"

	secretMount             = "secret"
	networkAllocationKVPath = "parent-group-governance/network/allocation"
)

var requiredManualTokens = []ManualTokenRequirement{
	{Path: "parent-group-governance/terraform/state-backend", Field: "token"},
	{Path: "parent-group-governance/ai-provider-console/anthropic", Field: "anthropic_admin_api_key"},
	{Path: "parent-group-governance/github/publication", Field: "deploy_token"},
	{Path: "gitlab-ci-with-code-reviewer/terraform/state-backend", Field: "token"},
	{Path: "gitlab-ci-with-code-reviewer/integration/code-reviewer-bot", Field: "token"},
	{Path: "gitlab-ci-with-code-reviewer/integration/auto-version-tag-bot", Field: "token"},
}

// ManualTokenRequirement identifies one KV v2 path and field that an operator must write manually.
type ManualTokenRequirement struct {
	Path  string
	Field string
}

// VaultObserverDeps injects Vault status/KV clients and lifecycle actions for Vault nodes.
type VaultObserverDeps struct {
	ProjectRoot          string
	Home                 string
	PublishIP            string
	RootHygieneDeps      []string
	InspectSealStatus    func(ctx context.Context) vaultclient.SealStatus
	VerifyFactoryDefault func(ctx context.Context) (bool, string, error)
	HasSecretMount       func(ctx context.Context) (bool, error)
	ReadKVMap            func(ctx context.Context, mount, path string) (map[string]string, bool, error)
	WriteKVMap           func(ctx context.Context, mount, path string, data map[string]string) error
	VerifyAdminProxy     func(ctx context.Context) (bool, error)
	InitVault            func(ctx context.Context, req ConvergeContext) error
	UnsealVault          func(ctx context.Context, req ConvergeContext) error
	EnableKVSecret       func(ctx context.Context, req ConvergeContext) error
	RevokeRootToken      func(ctx context.Context, req ConvergeContext) error
}

// RequiredManualTokens returns the KV v2 paths and fields that must be manually written to secret/ before Stage 3.
func RequiredManualTokens() []ManualTokenRequirement {
	return slices.Clone(requiredManualTokens)
}

// BuildVaultNodes constructs the DAG nodes covering Bastion Vault initialization, bootstrap facts, manual tokens, and hygiene.
func BuildVaultNodes(deps VaultObserverDeps) []Node {
	return []Node{
		&funcNode{
			id:    NodeVaultInitialized,
			stage: StageCoreContainers,
			deps:  []string{NodeContainerCore},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectVaultInitialized(ctx, deps)
			},
			converge: callConvergeAction(NodeVaultInitialized, deps.InitVault),
		},
		&funcNode{
			id:    NodeVaultUnsealed,
			stage: StageCoreContainers,
			deps:  []string{NodeVaultInitialized},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectVaultUnsealed(ctx, deps), nil
			},
			converge: callConvergeAction(NodeVaultUnsealed, deps.UnsealVault),
		},
		&funcNode{
			id:       NodeVaultKVSecret,
			stage:    StageCoreContainers,
			deps:     []string{NodeVaultUnsealed},
			inspect:  func(ctx context.Context, _ ObserveMode) (NodeReport, error) { return inspectVaultKVSecret(ctx, deps) },
			converge: callConvergeAction(NodeVaultKVSecret, deps.EnableKVSecret),
		},
		&funcNode{
			id:    NodeVaultNetworkAllocation,
			stage: StageBootstrapFacts,
			deps:  []string{NodeVaultKVSecret},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectVaultNetworkAllocation(ctx, deps)
			},
			converge: func(ctx context.Context, _ ConvergeContext) error {
				return convergeVaultNetworkAllocation(ctx, deps)
			},
		},
		&funcNode{
			id:    NodeVaultManualTokens,
			stage: StageBootstrapFacts,
			deps:  []string{NodeVaultKVSecret},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectVaultManualTokens(ctx, deps)
			},
			converge: func(context.Context, ConvergeContext) error {
				return errors.New("converge: vault.manual_tokens is observe-only; write tokens manually with vault kv put")
			},
		},
		&funcNode{
			id:    NodeVaultRootHygiene,
			stage: StageDownstream,
			deps:  slices.Clone(deps.RootHygieneDeps),
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectVaultRootHygiene(ctx, deps)
			},
			converge: callConvergeAction(NodeVaultRootHygiene, deps.RevokeRootToken),
		},
	}
}

func inspectVaultInitialized(ctx context.Context, deps VaultObserverDeps) (NodeReport, error) {
	if deps.InspectSealStatus == nil {
		return NodeReport{ID: NodeVaultInitialized, Stage: StageCoreContainers, State: StateBlocked, Summary: "seal inspector not configured"}, nil
	}
	st := deps.InspectSealStatus(ctx)
	if !st.Reachable {
		return NodeReport{
			ID:      NodeVaultInitialized,
			Stage:   StageCoreContainers,
			State:   StateBlocked,
			Summary: "Bastion Vault unreachable",
			Hint:    "ensure core containers are running before inspecting Vault",
		}, nil
	}
	if st.Initialized {
		return NodeReport{ID: NodeVaultInitialized, Stage: StageCoreContainers, State: StateConverged, Summary: "Bastion Vault initialized"}, nil
	}
	if deps.VerifyFactoryDefault != nil {
		ready, retained, err := deps.VerifyFactoryDefault(ctx)
		if err != nil {
			return NodeReport{}, err
		}
		if !ready {
			return NodeReport{
				ID:      NodeVaultInitialized,
				Stage:   StageCoreContainers,
				State:   StateBlocked,
				Summary: "service retains rotated password: " + retained,
				Hint:    "rebuild retained service volume before vault init: " + retained,
			}, nil
		}
	}
	return NodeReport{ID: NodeVaultInitialized, Stage: StageCoreContainers, State: StateAbsent, Summary: "Bastion Vault uninitialized"}, nil
}

func inspectVaultUnsealed(ctx context.Context, deps VaultObserverDeps) NodeReport {
	if deps.InspectSealStatus == nil {
		return NodeReport{ID: NodeVaultUnsealed, Stage: StageCoreContainers, State: StateBlocked, Summary: "seal inspector not configured"}
	}
	st := deps.InspectSealStatus(ctx)
	if !st.Reachable || !st.Initialized {
		return NodeReport{ID: NodeVaultUnsealed, Stage: StageCoreContainers, State: StateBlocked, Summary: "Bastion Vault not ready for unseal"}
	}
	if !st.Sealed {
		return NodeReport{ID: NodeVaultUnsealed, Stage: StageCoreContainers, State: StateConverged, Summary: "Bastion Vault unsealed"}
	}
	unsealKeyPath := filepath.Join(deps.ProjectRoot, "vault", "keys", "unseal.key")
	if _, err := os.Stat(unsealKeyPath); err != nil {
		return NodeReport{
			ID:      NodeVaultUnsealed,
			Stage:   StageCoreContainers,
			State:   StateBlocked,
			Summary: "Bastion Vault sealed and unseal.key missing",
			Hint:    "restore " + unsealKeyPath + " before unsealing",
		}
	}
	return NodeReport{ID: NodeVaultUnsealed, Stage: StageCoreContainers, State: StateDrifted, Summary: "Bastion Vault sealed"}
}

func inspectVaultKVSecret(ctx context.Context, deps VaultObserverDeps) (NodeReport, error) {
	if deps.InspectSealStatus == nil || deps.HasSecretMount == nil {
		return NodeReport{ID: NodeVaultKVSecret, Stage: StageCoreContainers, State: StateBlocked, Summary: "KV secret inspector not configured"}, nil
	}
	st := deps.InspectSealStatus(ctx)
	if !st.Reachable || !st.Initialized || st.Sealed {
		return NodeReport{ID: NodeVaultKVSecret, Stage: StageCoreContainers, State: StateBlocked, Summary: "Bastion Vault sealed or unreachable"}, nil
	}
	mounted, err := deps.HasSecretMount(ctx)
	if err != nil {
		return NodeReport{}, err
	}
	if mounted {
		return NodeReport{ID: NodeVaultKVSecret, Stage: StageCoreContainers, State: StateConverged, Summary: "secret/ KV v2 mounted"}, nil
	}
	return NodeReport{ID: NodeVaultKVSecret, Stage: StageCoreContainers, State: StateAbsent, Summary: "secret/ mount absent"}, nil
}

func inspectVaultNetworkAllocation(ctx context.Context, deps VaultObserverDeps) (NodeReport, error) {
	if deps.ReadKVMap == nil {
		return NodeReport{ID: NodeVaultNetworkAllocation, Stage: StageBootstrapFacts, State: StateBlocked, Summary: "KV reader not configured"}, nil
	}
	raw, found, err := deps.ReadKVMap(ctx, secretMount, networkAllocationKVPath)
	if err != nil {
		return NodeReport{}, err
	}
	if found && config.ValidateNetworkAllocation(raw, deps.PublishIP) == nil {
		return NodeReport{ID: NodeVaultNetworkAllocation, Stage: StageBootstrapFacts, State: StateConverged, Summary: "network allocation validated in Vault"}, nil
	}

	localPath := filepath.Join(deps.ProjectRoot, "network-allocation.json")
	if _, err := config.LoadAndValidateNetworkAllocation(localPath, deps.PublishIP); err != nil {
		return NodeReport{
			ID:      NodeVaultNetworkAllocation,
			Stage:   StageBootstrapFacts,
			State:   StateBlocked,
			Summary: "network allocation missing or invalid in Vault and local JSON",
			Hint:    fmt.Sprintf("provide a valid %s (%v)", localPath, err),
		}, nil
	}
	if found {
		return NodeReport{ID: NodeVaultNetworkAllocation, Stage: StageBootstrapFacts, State: StateDrifted, Summary: "Vault network allocation invalid; ready to sync from local JSON"}, nil
	}
	return NodeReport{ID: NodeVaultNetworkAllocation, Stage: StageBootstrapFacts, State: StateAbsent, Summary: "network allocation ready to populate from local JSON"}, nil
}

func convergeVaultNetworkAllocation(ctx context.Context, deps VaultObserverDeps) error {
	if deps.WriteKVMap == nil {
		return errors.New("converge: vault.network_allocation WriteKVMap not configured")
	}
	localPath := filepath.Join(deps.ProjectRoot, "network-allocation.json")
	data, err := config.LoadAndValidateNetworkAllocation(localPath, deps.PublishIP)
	if err != nil {
		return err
	}
	return deps.WriteKVMap(ctx, secretMount, networkAllocationKVPath, data)
}

func inspectVaultManualTokens(ctx context.Context, deps VaultObserverDeps) (NodeReport, error) {
	if deps.ReadKVMap == nil {
		return NodeReport{ID: NodeVaultManualTokens, Stage: StageBootstrapFacts, State: StateBlocked, Summary: "KV reader not configured"}, nil
	}
	var hints []string
	for _, req := range requiredManualTokens {
		data, found, err := deps.ReadKVMap(ctx, secretMount, req.Path)
		if err != nil {
			return NodeReport{}, err
		}
		if !found || data[req.Field] == "" {
			hints = append(hints, fmt.Sprintf("vault kv put %s/%s %s=<value>", secretMount, req.Path, req.Field))
		}
	}
	if len(hints) > 0 {
		return NodeReport{
			ID:      NodeVaultManualTokens,
			Stage:   StageBootstrapFacts,
			State:   StateBlocked,
			Summary: fmt.Sprintf("missing %d manual tokens", len(hints)),
			Hint:    strings.Join(hints, "; "),
		}, nil
	}
	return NodeReport{ID: NodeVaultManualTokens, Stage: StageBootstrapFacts, State: StateConverged, Summary: "all 6 manual tokens populated"}, nil
}

func inspectVaultRootHygiene(ctx context.Context, deps VaultObserverDeps) (NodeReport, error) {
	if deps.VerifyAdminProxy == nil {
		return NodeReport{ID: NodeVaultRootHygiene, Stage: StageDownstream, State: StateBlocked, Summary: "admin proxy verifier not configured"}, nil
	}
	active, err := deps.VerifyAdminProxy(ctx)
	if err != nil {
		return NodeReport{}, err
	}
	if !active {
		return NodeReport{
			ID:      NodeVaultRootHygiene,
			Stage:   StageDownstream,
			State:   StateBlocked,
			Summary: "administrator proxy inactive",
			Hint:    "verify administrator Vault Proxy before revoking root token",
		}, nil
	}
	tokenPath := filepath.Join(deps.Home, ".vault-token")
	_, statErr := os.Stat(tokenPath)
	if errors.Is(statErr, fs.ErrNotExist) {
		return NodeReport{ID: NodeVaultRootHygiene, Stage: StageDownstream, State: StateConverged, Summary: "administrator proxy active and ~/.vault-token revoked"}, nil
	}
	if statErr != nil {
		return NodeReport{}, fmt.Errorf("converge: stat %s: %w", tokenPath, statErr)
	}
	return NodeReport{
		ID:      NodeVaultRootHygiene,
		Stage:   StageDownstream,
		State:   StateDrifted,
		Summary: "~/.vault-token still present on disk",
		Hint:    "run ./governance vault revoke-root",
	}, nil
}
