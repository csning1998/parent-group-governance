// Package converge models the workstation convergence DAG and orchestrates four-state observation and execution.
package converge

import (
	"context"
	"io"
)

// BecomePassword encapsulates a privilege-escalation password and suppresses plaintext leakage during formatting.
type BecomePassword string

// String masks the password value to prevent accidental plaintext logging.
func (BecomePassword) String() string { return "[REDACTED]" }

// GoString masks the password value in %#v formatting.
func (BecomePassword) GoString() string { return "[REDACTED]" }

// Value returns the underlying plaintext password for subprocess environment injection.
func (p BecomePassword) Value() string { return string(p) }

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

// ObserveEvent reports per-node progress during DAG observation.
type ObserveEvent struct {
	Index  int
	Total  int
	NodeID string
	Stage  Stage
	Done   bool
	State  NodeState
}

// ConvergeContext supplies shared runtime parameters to a node's Converge step.
type ConvergeContext struct {
	BecomePassword BecomePassword
	AutoApprove    bool
	Stdin          io.Reader
	Stdout         io.Writer
	Stderr         io.Writer
}

// Node defines a single inspectable and convergable unit in the convergence DAG.
type Node interface {
	ID() string
	Stage() Stage
	DependsOn() []string
	RequiresBecome() bool
	Inspect(ctx context.Context, mode ObserveMode) (NodeReport, error)
	Converge(ctx context.Context, req ConvergeContext) error
}

type funcNode struct {
	id             string
	stage          Stage
	deps           []string
	requiresBecome bool
	inspect        func(ctx context.Context, mode ObserveMode) (NodeReport, error)
	converge       func(ctx context.Context, req ConvergeContext) error
}

func (n *funcNode) ID() string           { return n.id }
func (n *funcNode) Stage() Stage         { return n.stage }
func (n *funcNode) DependsOn() []string  { return n.deps }
func (n *funcNode) RequiresBecome() bool { return n.requiresBecome }

func (n *funcNode) Inspect(ctx context.Context, mode ObserveMode) (NodeReport, error) {
	return n.inspect(ctx, mode)
}

func (n *funcNode) Converge(ctx context.Context, req ConvergeContext) error {
	return n.converge(ctx, req)
}
