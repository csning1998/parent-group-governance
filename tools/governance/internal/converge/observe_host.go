package converge

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
)

const (
	// NodeHostTools verifies required workstation CLI binaries on PATH.
	NodeHostTools = "host.tools"
	// NodeHostEnvFile inspects .env completeness and SonarQube DB volume guard.
	NodeHostEnvFile = "host.env_file"
	// NodeHostSELinux inspects workstation SELinux policies and file contexts.
	NodeHostSELinux = "host.selinux"
	// NodeHostTLSCA inspects local CA and Vault listener/terminator TLS certificates.
	NodeHostTLSCA = "host.tls_ca"
	// NodeHostLibvirt inspects libvirt network, firewalld, and rendered Vault/HAProxy configs.
	NodeHostLibvirt = "host.libvirt"
	// NodeHostVaultProxy inspects operator Vault Proxy systemd units and mTLS certificates.
	NodeHostVaultProxy = "host.vault_proxy"
	// NodeContainerCore inspects core Podman containers for Vault, SonarQube, and GitLab Runner.
	NodeContainerCore = "container.core"
	// NodeHostVaultAudit inspects Vault audit systemd units and timer configuration.
	NodeHostVaultAudit = "host.vault_audit"
	// NodeHostTelemetry inspects publish SAN coverage, host telemetry, and terminators.
	NodeHostTelemetry = "host.telemetry"
)

var (
	requiredHostBinaries = []string{"terraform", "vault", "ansible", "direnv", "podman"}
	requiredEnvKeys      = []string{
		config.KeyProjectRoot,
		config.KeyHostUID,
		config.KeyHostGID,
		config.KeyUname,
		config.KeyUhome,
		config.KeySonarQubeDBPassword,
	}
	requiredTLSPairs = []string{"ca-ml-dsa-87", "ca-ec-p384", "loopback", "publish", "terminator-client"}
	coreContainers   = []string{
		"parent-group-governance-vault-bastion",
		"parent-group-governance-vault-bastion-terminator",
		"parent-group-governance-sonarqube-postgres",
		"parent-group-governance-sonarqube",
		"parent-group-governance-gitlab-runner",
	}
)

// ContainerState describes the runtime and health state of one local Podman container.
type ContainerState struct {
	Name    string
	Running bool
	Healthy bool
}

// HostObserverDeps injects filesystem roots, environment probes, and convergence actions for host nodes.
type HostObserverDeps struct {
	ProjectRoot       string
	Home              string
	LookPath          func(file string) (string, error)
	InspectContainers func(ctx context.Context) ([]ContainerState, error)
	InspectSELinux    func(ctx context.Context, mode ObserveMode) (NodeState, string, error)
	InspectLibvirt    func(ctx context.Context, mode ObserveMode) (NodeState, string, error)
	InspectVaultProxy func(ctx context.Context, mode ObserveMode) (NodeState, string, error)
	InspectVaultAudit func(ctx context.Context, mode ObserveMode) (NodeState, string, error)
	InspectTelemetry  func(ctx context.Context, mode ObserveMode) (NodeState, string, error)
	BootstrapEnv      func(ctx context.Context, req ConvergeContext) error
	ApplySELinux      func(ctx context.Context, req ConvergeContext) error
	EnsureTLSCA       func(ctx context.Context, req ConvergeContext) error
	ApplyLibvirt      func(ctx context.Context, req ConvergeContext) error
	ApplyVaultProxy   func(ctx context.Context, req ConvergeContext) error
	StartContainers   func(ctx context.Context, req ConvergeContext) error
	ApplyVaultAudit   func(ctx context.Context, req ConvergeContext) error
	ApplyTelemetry    func(ctx context.Context, req ConvergeContext) error
}

// BuildHostNodes constructs the DAG nodes covering Stage 0, Stage 1 container.core, and Stage 4 host observability.
func BuildHostNodes(deps HostObserverDeps) []Node {
	lookPath := deps.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	return []Node{
		&funcNode{
			id:      NodeHostTools,
			stage:   StageHostPrereqs,
			inspect: func(context.Context, ObserveMode) (NodeReport, error) { return inspectHostTools(lookPath), nil },
			converge: func(context.Context, ConvergeContext) error {
				return errors.New("converge: install missing host binaries manually")
			},
		},
		&funcNode{
			id:       NodeHostEnvFile,
			stage:    StageHostPrereqs,
			deps:     []string{NodeHostTools},
			inspect:  func(context.Context, ObserveMode) (NodeReport, error) { return inspectHostEnvFile(deps.ProjectRoot) },
			converge: callConvergeAction(NodeHostEnvFile, deps.BootstrapEnv),
		},
		buildDelegatedHostNode(NodeHostSELinux, StageHostPrereqs, []string{NodeHostEnvFile}, true, deps.InspectSELinux, deps.ApplySELinux),
		&funcNode{
			id:       NodeHostTLSCA,
			stage:    StageHostPrereqs,
			deps:     []string{NodeHostSELinux},
			inspect:  func(context.Context, ObserveMode) (NodeReport, error) { return inspectHostTLSCA(deps.ProjectRoot), nil },
			converge: callConvergeAction(NodeHostTLSCA, deps.EnsureTLSCA),
		},
		buildDelegatedHostNode(NodeHostLibvirt, StageHostPrereqs, []string{NodeHostTLSCA}, true, deps.InspectLibvirt, deps.ApplyLibvirt),
		buildDelegatedHostNode(NodeHostVaultProxy, StageHostPrereqs, []string{NodeHostLibvirt}, true, deps.InspectVaultProxy, deps.ApplyVaultProxy),
		&funcNode{
			id:    NodeContainerCore,
			stage: StageCoreContainers,
			deps:  []string{NodeHostVaultProxy},
			inspect: func(ctx context.Context, _ ObserveMode) (NodeReport, error) {
				return inspectContainerCore(ctx, deps.InspectContainers)
			},
			converge: callConvergeAction(NodeContainerCore, deps.StartContainers),
		},
		buildDelegatedHostNode(NodeHostVaultAudit, StageBastionObservability, []string{"terraform.foundation_vault_bastion"}, false, deps.InspectVaultAudit, deps.ApplyVaultAudit),
		buildDelegatedHostNode(NodeHostTelemetry, StageBastionObservability, []string{"terraform.foundation_vault_bastion"}, true, deps.InspectTelemetry, deps.ApplyTelemetry),
	}
}

func buildDelegatedHostNode(
	id string,
	stage Stage,
	deps []string,
	requiresBecome bool,
	inspectFn func(ctx context.Context, mode ObserveMode) (NodeState, string, error),
	convergeFn func(ctx context.Context, req ConvergeContext) error,
) Node {
	return &funcNode{
		id:             id,
		stage:          stage,
		deps:           deps,
		requiresBecome: requiresBecome,
		inspect: func(ctx context.Context, mode ObserveMode) (NodeReport, error) {
			if inspectFn == nil {
				return NodeReport{ID: id, Stage: stage, State: StateBlocked, Summary: "inspector not configured", RequiresBecome: requiresBecome}, nil
			}
			state, summary, err := inspectFn(ctx, mode)
			if err != nil {
				return NodeReport{}, err
			}
			return NodeReport{ID: id, Stage: stage, State: state, Summary: summary, RequiresBecome: requiresBecome}, nil
		},
		converge: callConvergeAction(id, convergeFn),
	}
}

func callConvergeAction(id string, fn func(ctx context.Context, req ConvergeContext) error) func(context.Context, ConvergeContext) error {
	return func(ctx context.Context, req ConvergeContext) error {
		if fn == nil {
			return fmt.Errorf("converge: %s handler not configured", id)
		}
		return fn(ctx, req)
	}
}

func inspectHostTools(lookPath func(string) (string, error)) NodeReport {
	var missing []string
	for _, bin := range requiredHostBinaries {
		if _, err := lookPath(bin); err != nil {
			missing = append(missing, bin)
		}
	}
	if len(missing) > 0 {
		return NodeReport{
			ID:      NodeHostTools,
			Stage:   StageHostPrereqs,
			State:   StateBlocked,
			Summary: fmt.Sprintf("missing %d required tools", len(missing)),
			Hint:    "install missing tools on PATH: " + strings.Join(missing, ", "),
		}
	}
	return NodeReport{ID: NodeHostTools, Stage: StageHostPrereqs, State: StateConverged, Summary: "all 5 workstation binaries available"}
}

func inspectHostEnvFile(projectRoot string) (NodeReport, error) {
	envPath := filepath.Join(projectRoot, ".env")
	postgresDataNonEmpty, err := isNonEmptyDir(filepath.Join(projectRoot, "sonarqube", "postgres-data"))
	if err != nil {
		return NodeReport{}, err
	}

	_, statErr := os.Stat(envPath)
	if errors.Is(statErr, fs.ErrNotExist) {
		if postgresDataNonEmpty {
			return NodeReport{
				ID:      NodeHostEnvFile,
				Stage:   StageHostPrereqs,
				State:   StateBlocked,
				Summary: ".env missing while sonarqube/postgres-data is initialized",
				Hint:    "restore .env with SONARQUBE_DB_PASSWORD or clean sonarqube/postgres-data before bootstrapping",
			}, nil
		}
		return NodeReport{ID: NodeHostEnvFile, Stage: StageHostPrereqs, State: StateAbsent, Summary: ".env does not exist"}, nil
	}
	if statErr != nil {
		return NodeReport{}, fmt.Errorf("converge: stat %s: %w", envPath, statErr)
	}

	env, err := config.Load(envPath)
	if err != nil {
		return NodeReport{}, err
	}
	return classifyLoadedEnv(env, postgresDataNonEmpty), nil
}

func classifyLoadedEnv(env *config.Env, postgresDataNonEmpty bool) NodeReport {
	if env.Get(config.KeySonarQubeDBPassword) == "" && postgresDataNonEmpty {
		return NodeReport{
			ID:      NodeHostEnvFile,
			Stage:   StageHostPrereqs,
			State:   StateBlocked,
			Summary: "SONARQUBE_DB_PASSWORD missing while sonarqube/postgres-data is initialized",
			Hint:    "restore SONARQUBE_DB_PASSWORD into .env before bootstrapping",
		}
	}
	var missing []string
	for _, k := range requiredEnvKeys {
		if env.Get(k) == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return NodeReport{
			ID:      NodeHostEnvFile,
			Stage:   StageHostPrereqs,
			State:   StateDrifted,
			Summary: "missing .env keys: " + strings.Join(missing, ", "),
		}
	}
	return NodeReport{ID: NodeHostEnvFile, Stage: StageHostPrereqs, State: StateConverged, Summary: "all 6 .env keys populated"}
}

func isNonEmptyDir(dir string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("converge: read dir %s: %w", dir, err)
	}
	return len(entries) > 0, nil
}

func inspectHostTLSCA(projectRoot string) NodeReport {
	tlsDir := filepath.Join(projectRoot, "vault", "tls")
	totalExpected := len(requiredTLSPairs) * 2
	present := 0
	for _, name := range requiredTLSPairs {
		for _, suffix := range []string{".pem", "-key.pem"} {
			if _, err := os.Stat(filepath.Join(tlsDir, name+suffix)); err == nil {
				present++
			}
		}
	}
	switch present {
	case 0:
		return NodeReport{ID: NodeHostTLSCA, Stage: StageHostPrereqs, State: StateAbsent, Summary: "vault/tls certificates absent"}
	case totalExpected:
		return NodeReport{ID: NodeHostTLSCA, Stage: StageHostPrereqs, State: StateConverged, Summary: "all 5 TLS cert/key pairs present"}
	default:
		return NodeReport{
			ID:      NodeHostTLSCA,
			Stage:   StageHostPrereqs,
			State:   StateDrifted,
			Summary: fmt.Sprintf("%d of %d TLS files present", present, totalExpected),
		}
	}
}

func inspectContainerCore(ctx context.Context, inspectFn func(context.Context) ([]ContainerState, error)) (NodeReport, error) {
	if inspectFn == nil {
		return NodeReport{ID: NodeContainerCore, Stage: StageCoreContainers, State: StateBlocked, Summary: "container inspector not configured"}, nil
	}
	states, err := inspectFn(ctx)
	if err != nil {
		return NodeReport{}, err
	}
	byName := make(map[string]ContainerState, len(states))
	for _, st := range states {
		byName[st.Name] = st
	}
	running, healthy := 0, 0
	for _, name := range coreContainers {
		st := byName[name]
		if st.Running {
			running++
			if st.Healthy {
				healthy++
			}
		}
	}
	switch {
	case running == 0:
		return NodeReport{ID: NodeContainerCore, Stage: StageCoreContainers, State: StateAbsent, Summary: "core containers not running"}, nil
	case healthy == len(coreContainers):
		return NodeReport{ID: NodeContainerCore, Stage: StageCoreContainers, State: StateConverged, Summary: "all 5 core containers running and healthy"}, nil
	default:
		return NodeReport{
			ID:      NodeContainerCore,
			Stage:   StageCoreContainers,
			State:   StateDrifted,
			Summary: fmt.Sprintf("%d/%d running, %d/%d healthy", running, len(coreContainers), healthy, len(coreContainers)),
		}, nil
	}
}
