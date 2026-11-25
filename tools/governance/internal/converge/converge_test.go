package converge

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/terraform"
)

type stubNode struct {
	id             string
	stage          Stage
	deps           []string
	requiresBecome bool
	state          NodeState
	hint           string
	inspectErr     error
	convergeErr    error

	inspectCalls int
	convergeReqs []ConvergeContext
	onConverge   func(id string)
}

func (n *stubNode) ID() string           { return n.id }
func (n *stubNode) Stage() Stage         { return n.stage }
func (n *stubNode) DependsOn() []string  { return n.deps }
func (n *stubNode) RequiresBecome() bool { return n.requiresBecome }

func (n *stubNode) Inspect(_ context.Context, _ ObserveMode) (NodeReport, error) {
	n.inspectCalls++
	if n.inspectErr != nil {
		return NodeReport{}, n.inspectErr
	}
	return NodeReport{
		ID:             n.id,
		Stage:          n.stage,
		State:          n.state,
		Hint:           n.hint,
		RequiresBecome: n.requiresBecome,
	}, nil
}

func (n *stubNode) Converge(_ context.Context, req ConvergeContext) error {
	n.convergeReqs = append(n.convergeReqs, req)
	if n.onConverge != nil {
		n.onConverge(n.id)
	}
	return n.convergeErr
}

func TestNewGraphValidatesTopology(t *testing.T) {
	t.Run("duplicate id", func(t *testing.T) {
		_, err := NewGraph(
			&stubNode{id: "example.a", stage: StageHostPrereqs},
			&stubNode{id: "example.a", stage: StageCoreContainers},
		)
		if !errors.Is(err, ErrDuplicateNode) {
			t.Fatalf("NewGraph error = %v, want errors.Is(_, ErrDuplicateNode)", err)
		}
	})

	t.Run("unknown dependency", func(t *testing.T) {
		_, err := NewGraph(&stubNode{id: "example.a", stage: StageHostPrereqs, deps: []string{"example.missing"}})
		if !errors.Is(err, ErrUnknownDependency) {
			t.Fatalf("NewGraph error = %v, want errors.Is(_, ErrUnknownDependency)", err)
		}
	})

	t.Run("cycle", func(t *testing.T) {
		_, err := NewGraph(
			&stubNode{id: "example.a", stage: StageHostPrereqs, deps: []string{"example.b"}},
			&stubNode{id: "example.b", stage: StageHostPrereqs, deps: []string{"example.a"}},
		)
		if !errors.Is(err, ErrCycleDetected) {
			t.Fatalf("NewGraph error = %v, want errors.Is(_, ErrCycleDetected)", err)
		}
	})

	t.Run("deterministic topological order", func(t *testing.T) {
		g := mustNewGraph(t,
			&stubNode{id: "example.d", stage: StageCoreContainers, deps: []string{"example.b"}},
			&stubNode{id: "example.c", stage: StageHostPrereqs},
			&stubNode{id: "example.b", stage: StageHostPrereqs, deps: []string{"example.c"}},
			&stubNode{id: "example.a", stage: StageHostPrereqs},
		)
		assertNodeIDsEqual(t, nodeIDs(g.Order()), []string{"example.a", "example.c", "example.b", "example.d"})
	})
}

func TestGraphSubgraphFiltersByNodeOrStage(t *testing.T) {
	g := mustNewGraph(t,
		&stubNode{id: "example.root", stage: StageHostPrereqs},
		&stubNode{id: "example.s1", stage: StageCoreContainers, deps: []string{"example.root"}},
		&stubNode{id: "example.side", stage: StageCoreContainers},
		&stubNode{id: "example.s2", stage: StageBootstrapFacts, deps: []string{"example.s1"}},
	)

	cases := []struct {
		name    string
		target  string
		wantIDs []string
		wantErr error
	}{
		{name: "empty target returns full order", target: "", wantIDs: []string{"example.root", "example.s1", "example.side", "example.s2"}},
		{name: "node target includes transitive upstreams", target: "example.s2", wantIDs: []string{"example.root", "example.s1", "example.s2"}},
		{name: "numeric stage selector", target: "1", wantIDs: []string{"example.root", "example.s1", "example.side"}},
		{name: "prefixed stage selector", target: "stage-1", wantIDs: []string{"example.root", "example.s1", "example.side"}},
		{name: "unknown target returns error", target: "example.unknown", wantErr: ErrUnknownTarget},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nodes, err := g.Subgraph(tc.target)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Subgraph(%q) error = %v, want errors.Is(_, %v)", tc.target, err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Subgraph(%q) unexpected error: %v", tc.target, err)
			}
			assertNodeIDsEqual(t, nodeIDs(nodes), tc.wantIDs)
		})
	}
}

func TestObservePropagatesBlockedDownstream(t *testing.T) {
	blockedUpstream := &stubNode{id: "example.gate", stage: StageHostPrereqs, state: StateBlocked, hint: "manual token missing"}
	downstream := &stubNode{id: "example.child", stage: StageCoreContainers, deps: []string{"example.gate"}, state: StateAbsent}
	independent := &stubNode{id: "example.other", stage: StageCoreContainers, state: StateConverged}

	g := mustNewGraph(t, blockedUpstream, downstream, independent)
	reports, err := Observe(context.Background(), g, ObserveFast, "")
	if err != nil {
		t.Fatalf("Observe unexpected error: %v", err)
	}

	assertReportState(t, reports, "example.gate", StateBlocked)
	childReport := assertReportState(t, reports, "example.child", StateBlocked)
	if !strings.Contains(childReport.Hint, "example.gate") {
		t.Errorf("downstream blocked hint = %q, want reference to example.gate", childReport.Hint)
	}
	if downstream.inspectCalls != 0 {
		t.Errorf("downstream inspectCalls = %d, want 0", downstream.inspectCalls)
	}
	assertReportState(t, reports, "example.other", StateConverged)
}

func TestConvergeExecutesAbsentAndDriftedSkipsConvergedAndHaltsBlockedBranch(t *testing.T) {
	var order []string
	record := func(id string) { order = append(order, id) }

	converged := &stubNode{id: "example.done", stage: StageHostPrereqs, state: StateConverged, onConverge: record}
	absent := &stubNode{id: "example.absent", stage: StageHostPrereqs, deps: []string{"example.done"}, state: StateAbsent, onConverge: record}
	drifted := &stubNode{id: "example.drifted", stage: StageCoreContainers, deps: []string{"example.absent"}, state: StateDrifted, onConverge: record}
	blocked := &stubNode{id: "example.blocked", stage: StageHostPrereqs, state: StateBlocked, hint: "fix manually", onConverge: record}
	blockedChild := &stubNode{id: "example.blocked_child", stage: StageCoreContainers, deps: []string{"example.blocked"}, state: StateAbsent, onConverge: record}

	g := mustNewGraph(t, converged, absent, drifted, blocked, blockedChild)
	res, err := Converge(context.Background(), g, ConvergeOptions{Mode: ObserveFast})
	if err != nil {
		t.Fatalf("Converge unexpected error: %v", err)
	}

	assertNodeIDsEqual(t, order, []string{"example.absent", "example.drifted"})
	assertNodeIDsEqual(t, res.Executed, []string{"example.absent", "example.drifted"})
	assertNodeIDsEqual(t, res.Skipped, []string{"example.done"})
	assertNodeIDsEqual(t, res.Blocked, []string{"example.blocked", "example.blocked_child"})
}

func TestConvergeDryRunPlansWithoutMutatingOrPromptingBecome(t *testing.T) {
	absent := &stubNode{id: "example.absent", stage: StageHostPrereqs, state: StateAbsent, requiresBecome: true}
	drifted := &stubNode{id: "example.drifted", stage: StageCoreContainers, deps: []string{"example.absent"}, state: StateDrifted}
	converged := &stubNode{id: "example.done", stage: StageHostPrereqs, state: StateConverged}

	g := mustNewGraph(t, absent, drifted, converged)
	promptCalls := 0
	res, err := Converge(context.Background(), g, ConvergeOptions{
		Mode:   ObserveFast,
		DryRun: true,
		PromptBecome: func(context.Context) (BecomePassword, error) {
			promptCalls++
			return BecomePassword("example-become-pass"), nil
		},
	})
	if err != nil {
		t.Fatalf("Converge dry-run unexpected error: %v", err)
	}

	assertNodeIDsEqual(t, res.Planned, []string{"example.absent", "example.drifted"})
	assertNodeIDsEqual(t, res.Executed, nil)
	if len(absent.convergeReqs) != 0 || len(drifted.convergeReqs) != 0 {
		t.Errorf("DryRun mutated nodes: absent=%d drifted=%d", len(absent.convergeReqs), len(drifted.convergeReqs))
	}
	if promptCalls != 0 {
		t.Errorf("DryRun PromptBecome calls = %d, want 0", promptCalls)
	}
}

func TestConvergePromptsBecomeOnceAndStopsOnFailure(t *testing.T) {
	t.Run("prompts once and shares password", func(t *testing.T) {
		first := &stubNode{id: "example.first", stage: StageHostPrereqs, state: StateAbsent, requiresBecome: true}
		second := &stubNode{id: "example.second", stage: StageCoreContainers, deps: []string{"example.first"}, state: StateDrifted, requiresBecome: true}
		g := mustNewGraph(t, first, second)

		promptCalls := 0
		res, err := Converge(context.Background(), g, ConvergeOptions{
			Mode: ObserveFast,
			PromptBecome: func(context.Context) (BecomePassword, error) {
				promptCalls++
				return BecomePassword("example-sudo-secret"), nil
			},
		})
		if err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if promptCalls != 1 {
			t.Errorf("PromptBecome calls = %d, want 1", promptCalls)
		}
		assertNodeIDsEqual(t, res.Executed, []string{"example.first", "example.second"})
		assertBecomePassword(t, first, "example-sudo-secret")
		assertBecomePassword(t, second, "example-sudo-secret")
	})

	t.Run("missing become callback fails before execution", func(t *testing.T) {
		first := &stubNode{id: "example.first", stage: StageHostPrereqs, state: StateAbsent, requiresBecome: true}
		g := mustNewGraph(t, first)

		_, err := Converge(context.Background(), g, ConvergeOptions{Mode: ObserveFast})
		if !errors.Is(err, ErrBecomePromptMissing) {
			t.Fatalf("Converge error = %v, want errors.Is(_, ErrBecomePromptMissing)", err)
		}
		if len(first.convergeReqs) != 0 {
			t.Errorf("node executed %d times without become callback, want 0", len(first.convergeReqs))
		}
	})

	t.Run("stops immediately when become node fails", func(t *testing.T) {
		boom := errors.New("incorrect password")
		first := &stubNode{id: "example.first", stage: StageHostPrereqs, state: StateAbsent, requiresBecome: true, convergeErr: boom}
		second := &stubNode{id: "example.second", stage: StageHostPrereqs, state: StateAbsent, requiresBecome: true}
		g := mustNewGraph(t, first, second)

		_, err := Converge(context.Background(), g, ConvergeOptions{
			Mode:         ObserveFast,
			PromptBecome: func(context.Context) (BecomePassword, error) { return BecomePassword("wrong"), nil },
		})
		if !errors.Is(err, boom) {
			t.Fatalf("Converge error = %v, want errors.Is(_, boom)", err)
		}
		if len(first.convergeReqs) != 1 || len(second.convergeReqs) != 0 {
			t.Errorf("execution counts = (%d, %d), want (1, 0)", len(first.convergeReqs), len(second.convergeReqs))
		}
	})
}

func TestBecomePasswordSuppressesPlaintextFormatting(t *testing.T) {
	const plaintext = "example-plaintext-become-secret"
	pw := BecomePassword(plaintext)
	formatted := []string{
		pw.String(),
		fmt.Sprintf("%v", pw),
		fmt.Sprintf("%#v", pw),
		fmt.Sprintf("%+v", ConvergeContext{BecomePassword: pw}),
	}
	for _, out := range formatted {
		if strings.Contains(out, plaintext) {
			t.Errorf("formatted output %q leaked plaintext password", out)
		}
		if !strings.Contains(out, "[REDACTED]") {
			t.Errorf("formatted output %q omitted [REDACTED]", out)
		}
	}
	if pw.Value() != plaintext {
		t.Errorf("pw.Value() = %q, want %q", pw.Value(), plaintext)
	}
}

func mustNewGraph(t *testing.T, nodes ...Node) *Graph {
	t.Helper()
	g, err := NewGraph(nodes...)
	if err != nil {
		t.Fatalf("NewGraph unexpected error: %v", err)
	}
	if g == nil {
		t.Fatal("NewGraph returned nil graph")
	}
	return g
}

func nodeIDs(nodes []Node) []string {
	ids := make([]string, len(nodes))
	for i, n := range nodes {
		ids[i] = n.ID()
	}
	return ids
}

func assertNodeIDsEqual(t *testing.T, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("node IDs = %v, want %v", got, want)
	}
}

func assertReportState(t *testing.T, reports []NodeReport, id string, wantState NodeState) NodeReport {
	t.Helper()
	for _, r := range reports {
		if r.ID == id {
			if r.State != wantState {
				t.Errorf("report[%s].State = %q, want %q", id, r.State, wantState)
			}
			return r
		}
	}
	t.Fatalf("report for %q missing from %v", id, reports)
	return NodeReport{}
}

func assertBecomePassword(t *testing.T, node *stubNode, want string) {
	t.Helper()
	if len(node.convergeReqs) != 1 {
		t.Fatalf("node %q converge calls = %d, want 1", node.id, len(node.convergeReqs))
	}
	if node.convergeReqs[0].BecomePassword.Value() != want {
		t.Errorf("node %q BecomePassword.Value() = %q, want %q", node.id, node.convergeReqs[0].BecomePassword.Value(), want)
	}
}

func TestObserveWithProgressEmitsStartAndDoneEvents(t *testing.T) {
	g := mustNewGraph(t,
		&stubNode{id: "example.first", stage: StageHostPrereqs, state: StateConverged},
		&stubNode{id: "example.second", stage: StageCoreContainers, deps: []string{"example.first"}, state: StateBlocked},
		&stubNode{id: "example.third", stage: StageBootstrapFacts, deps: []string{"example.second"}, state: StateAbsent},
	)

	var events []ObserveEvent
	reports, err := ObserveWithProgress(context.Background(), g, ObserveFast, "", func(ev ObserveEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatalf("ObserveWithProgress error = %v", err)
	}
	if len(reports) != 3 {
		t.Fatalf("reports len = %d, want 3", len(reports))
	}
	want := []ObserveEvent{
		{Index: 1, Total: 3, NodeID: "example.first", Stage: StageHostPrereqs, Done: false},
		{Index: 1, Total: 3, NodeID: "example.first", Stage: StageHostPrereqs, Done: true, State: StateConverged},
		{Index: 2, Total: 3, NodeID: "example.second", Stage: StageCoreContainers, Done: false},
		{Index: 2, Total: 3, NodeID: "example.second", Stage: StageCoreContainers, Done: true, State: StateBlocked},
		{Index: 3, Total: 3, NodeID: "example.third", Stage: StageBootstrapFacts, Done: false},
		{Index: 3, Total: 3, NodeID: "example.third", Stage: StageBootstrapFacts, Done: true, State: StateBlocked},
	}
	if !slices.Equal(events, want) {
		t.Fatalf("ObserveWithProgress events = %+v, want %+v", events, want)
	}

	var convergeEvents []ObserveEvent
	_, err = Converge(context.Background(), g, ConvergeOptions{
		DryRun: true,
		OnObserveProgress: func(ev ObserveEvent) {
			convergeEvents = append(convergeEvents, ev)
		},
	})
	if err != nil {
		t.Fatalf("Converge(DryRun) error = %v", err)
	}
	if !slices.Equal(convergeEvents, want) {
		t.Fatalf("Converge OnObserveProgress events = %+v, want %+v", convergeEvents, want)
	}
}

func TestConvergeReusesInitialReportsAndForwardsStdin(t *testing.T) {
	node := &stubNode{id: "example.one", stage: StageHostPrereqs, state: StateAbsent}
	g := mustNewGraph(t, node)
	stdin := strings.NewReader("yes\n")

	res, err := Converge(context.Background(), g, ConvergeOptions{
		InitialReports: []NodeReport{{ID: "example.one", Stage: StageHostPrereqs, State: StateAbsent}},
		Stdin:          stdin,
	})
	if err != nil {
		t.Fatalf("Converge(InitialReports) error = %v", err)
	}
	if node.inspectCalls != 0 || len(res.Executed) != 1 || node.convergeReqs[0].Stdin != stdin {
		t.Fatalf("inspectCalls=%d executed=%v gotStdin=%v, want (0, [example.one], same reader)", node.inspectCalls, res.Executed, node.convergeReqs[0].Stdin == stdin)
	}
}

func TestBuildTerraformNodesForwardsStdinToApplyLayer(t *testing.T) {
	var gotReq terraform.RunRequest
	nodes := BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:          "/tmp/example-root",
		HasOperatorCertMount: func(context.Context) (bool, error) { return true, nil },
		ApplyLayer: func(_ context.Context, req terraform.RunRequest) error {
			gotReq = req
			return nil
		},
	})
	stdin := strings.NewReader("yes\n")
	if err := nodes[0].Converge(context.Background(), ConvergeContext{Stdin: stdin}); err != nil {
		t.Fatalf("Converge error = %v", err)
	}
	if gotReq.Stdin != stdin {
		t.Fatalf("ApplyLayer received Stdin != ConvergeContext.Stdin")
	}
}
