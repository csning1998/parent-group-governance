package reconcile

import (
	"context"
	"errors"
	"fmt"
	"io"
)

// ErrBecomePromptMissing reports a convergence plan requiring become privileges without a PromptBecome callback.
var ErrBecomePromptMissing = errors.New("reconcile: become prompt callback is required")

// ConvergeOptions configures observation, filtering, dry-run behavior, and become password collection.
type ConvergeOptions struct {
	Target       string
	Mode         ObserveMode
	DryRun       bool
	AutoApprove  bool
	PromptBecome func(ctx context.Context) (string, error)
	Stdout       io.Writer
	Stderr       io.Writer
}

// ConvergeResult summarizes observation reports and execution outcomes for a Converge run.
type ConvergeResult struct {
	Reports  []NodeReport
	Planned  []string
	Executed []string
	Skipped  []string
	Blocked  []string
}

// Observe inspects the target subgraph in topological order and propagates Blocked state to downstream dependents.
func Observe(ctx context.Context, graph *Graph, mode ObserveMode, target string) ([]NodeReport, error) {
	mode = defaultObserveMode(mode)
	nodes, err := graph.Subgraph(target)
	if err != nil {
		return nil, err
	}

	reports := make([]NodeReport, 0, len(nodes))
	blockedBy := make(map[string]string)

	for _, node := range nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if rootBlocker, blocked := findBlockedUpstream(node.DependsOn(), blockedBy); blocked {
			blockedBy[node.ID()] = rootBlocker
			reports = append(reports, newUpstreamBlockedReport(node, rootBlocker))
			continue
		}
		report, err := inspectNode(ctx, node, mode)
		if err != nil {
			return nil, err
		}
		if report.State == StateBlocked {
			blockedBy[node.ID()] = node.ID()
		}
		reports = append(reports, report)
	}
	return reports, nil
}

// Converge observes the target subgraph and converges Absent and Drifted nodes whose upstreams are unblocked.
func Converge(ctx context.Context, graph *Graph, opts ConvergeOptions) (ConvergeResult, error) {
	opts.Mode = defaultObserveMode(opts.Mode)
	nodes, err := graph.Subgraph(opts.Target)
	if err != nil {
		return ConvergeResult{}, err
	}

	reports, err := Observe(ctx, graph, opts.Mode, opts.Target)
	if err != nil {
		return ConvergeResult{}, err
	}

	res, plannedNodes, needsBecome := classifyReports(reports, indexSubgraphNodes(nodes))
	if opts.DryRun || len(plannedNodes) == 0 {
		return res, nil
	}

	becomePass, err := resolveBecomePassword(ctx, needsBecome, opts.PromptBecome)
	if err != nil {
		return res, err
	}

	execCtx := ConvergeContext{
		BecomePassword: becomePass,
		AutoApprove:    opts.AutoApprove,
		Stdout:         opts.Stdout,
		Stderr:         opts.Stderr,
	}
	for _, node := range plannedNodes {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if err := node.Converge(ctx, execCtx); err != nil {
			return res, fmt.Errorf("reconcile: converge %s: %w", node.ID(), err)
		}
		res.Executed = append(res.Executed, node.ID())
	}
	return res, nil
}

func defaultObserveMode(mode ObserveMode) ObserveMode {
	if mode == "" {
		return ObserveFast
	}
	return mode
}

func findBlockedUpstream(deps []string, blockedBy map[string]string) (string, bool) {
	for _, dep := range deps {
		if rootBlocker, ok := blockedBy[dep]; ok {
			return rootBlocker, true
		}
	}
	return "", false
}

func newUpstreamBlockedReport(node Node, rootBlocker string) NodeReport {
	return NodeReport{
		ID:             node.ID(),
		Stage:          node.Stage(),
		State:          StateBlocked,
		Summary:        "blocked by upstream " + rootBlocker,
		Hint:           "resolve " + rootBlocker + " first",
		RequiresBecome: node.RequiresBecome(),
	}
}

func inspectNode(ctx context.Context, node Node, mode ObserveMode) (NodeReport, error) {
	report, err := node.Inspect(ctx, mode)
	if err != nil {
		return NodeReport{}, fmt.Errorf("reconcile: inspect %s: %w", node.ID(), err)
	}
	if report.ID == "" {
		report.ID = node.ID()
	}
	if report.Stage == 0 {
		report.Stage = node.Stage()
	}
	if !report.RequiresBecome {
		report.RequiresBecome = node.RequiresBecome()
	}
	return report, nil
}

func indexSubgraphNodes(nodes []Node) map[string]Node {
	byID := make(map[string]Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID()] = n
	}
	return byID
}

func classifyReports(reports []NodeReport, nodeByID map[string]Node) (ConvergeResult, []Node, bool) {
	res := ConvergeResult{Reports: reports}
	var plannedNodes []Node
	needsBecome := false

	for _, r := range reports {
		switch r.State {
		case StateConverged:
			res.Skipped = append(res.Skipped, r.ID)
		case StateBlocked:
			res.Blocked = append(res.Blocked, r.ID)
		case StateAbsent, StateDrifted:
			res.Planned = append(res.Planned, r.ID)
			plannedNodes = append(plannedNodes, nodeByID[r.ID])
			if r.RequiresBecome {
				needsBecome = true
			}
		}
	}
	return res, plannedNodes, needsBecome
}

func resolveBecomePassword(ctx context.Context, needsBecome bool, prompt func(context.Context) (string, error)) (string, error) {
	if !needsBecome {
		return "", nil
	}
	if prompt == nil {
		return "", ErrBecomePromptMissing
	}
	return prompt(ctx)
}
