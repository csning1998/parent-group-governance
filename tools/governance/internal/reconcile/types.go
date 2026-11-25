// Package reconcile models the workstation convergence DAG and orchestrates four-state observation and execution.
package reconcile

import (
	"context"
	"io"
)

// NodeState classifies the observed convergence state of one DAG node.
type NodeState string

const (
	// StateAbsent indicates expected artifacts do not exist yet and can be created via Converge.
	StateAbsent NodeState = "ABSENT"
	// StateConverged indicates observed state matches declared expectations.
	StateConverged NodeState = "CONVERGED"
	// StateDrifted indicates artifacts exist but diverge from declared expectations.
	StateDrifted NodeState = "DRIFTED"
	// StateBlocked indicates an external prerequisite, manual token, or direnv approval is missing.
	StateBlocked NodeState = "BLOCKED"
)

// ObserveMode controls inspection cost and depth.
type ObserveMode string

const (
	// ObserveFast performs cheap local, container, and Vault HTTP checks without Ansible check mode or terraform plan.
	ObserveFast ObserveMode = "fast"
	// ObserveDeep includes Ansible --check and terraform plan -detailed-exitcode on ready layers.
	ObserveDeep ObserveMode = "deep"
)

// Stage identifies the ordered bootstrap phase of a DAG node.
type Stage int

const (
	// StageHostPrereqs covers workstation host binaries, .env, SELinux, TLS CAs, libvirt, and Vault Proxy.
	StageHostPrereqs Stage = 0
	// StageCoreContainers covers core Podman services and Bastion Vault initialization/unseal/KV mount.
	StageCoreContainers Stage = 1
	// StageBootstrapFacts covers network allocation validation and the manual token gate.
	StageBootstrapFacts Stage = 2
	// StageTrustRoot covers the foundation-vault-bastion trust root layer.
	StageTrustRoot Stage = 3
	// StageBastionObservability covers Bastion host audit, telemetry, log shipper, and SonarQube admin rotation.
	StageBastionObservability Stage = 4
	// StageDownstream covers downstream Terraform layers, issued credentials, and root token hygiene.
	StageDownstream Stage = 5
)

// NodeReport captures the result of inspecting one node.
type NodeReport struct {
	ID             string
	Stage          Stage
	State          NodeState
	Summary        string
	Hint           string
	RequiresBecome bool
}

// ConvergeContext supplies shared runtime parameters to a node's Converge step.
type ConvergeContext struct {
	BecomePassword string
	AutoApprove    bool
	Stdout         io.Writer
	Stderr         io.Writer
}

// Node defines a single inspectable and convergable unit in the reconciliation DAG.
type Node interface {
	ID() string
	Stage() Stage
	DependsOn() []string
	RequiresBecome() bool
	Inspect(ctx context.Context, mode ObserveMode) (NodeReport, error)
	Converge(ctx context.Context, req ConvergeContext) error
}
