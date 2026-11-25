package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

type stubNode struct {
	id             string
	stage          converge.Stage
	deps           []string
	requiresBecome bool
	inspectFn      func(context.Context, converge.ObserveMode) (converge.NodeReport, error)
	convergeFn     func(context.Context, converge.ConvergeContext) error
}

func (n *stubNode) ID() string            { return n.id }
func (n *stubNode) Stage() converge.Stage { return n.stage }
func (n *stubNode) DependsOn() []string   { return n.deps }
func (n *stubNode) RequiresBecome() bool  { return n.requiresBecome }
func (n *stubNode) Inspect(ctx context.Context, mode converge.ObserveMode) (converge.NodeReport, error) {
	return n.inspectFn(ctx, mode)
}
func (n *stubNode) Converge(ctx context.Context, req converge.ConvergeContext) error {
	return n.convergeFn(ctx, req)
}

func TestFormatStatusTableRendersStagesStatesAndHints(t *testing.T) {
	reports := []converge.NodeReport{
		{ID: "host.tools", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "all 5 tools installed"},
		{ID: "host.env_file", Stage: converge.StageHostPrereqs, State: converge.StateAbsent, Summary: ".env missing"},
		{ID: "vault.unsealed", Stage: converge.StageCoreContainers, State: converge.StateDrifted, Summary: "vault sealed"},
		{ID: "vault.manual_tokens", Stage: converge.StageBootstrapFacts, State: converge.StateBlocked, Summary: "missing 1 token", Hint: "run vault kv put"},
	}

	var buf bytes.Buffer
	formatStatusTable(&buf, reports)
	out := buf.String()

	for _, want := range []string{
		"Stage 0",
		"Stage 1",
		"Stage 2",
		"host.tools",
		"CONVERGED",
		"ABSENT",
		"DRIFTED",
		"BLOCKED",
		"missing 1 token",
		"run vault kv put",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("formatStatusTable output missing %q:\n%s", want, out)
		}
	}
}

func TestStatusCommandObservesWithoutMutatingEnv(t *testing.T) {
	var modes []converge.ObserveMode
	var inspected []string
	g, err := converge.NewGraph(
		&stubNode{
			id:    "stage0.node",
			stage: converge.StageHostPrereqs,
			inspectFn: func(_ context.Context, m converge.ObserveMode) (converge.NodeReport, error) {
				modes = append(modes, m)
				inspected = append(inspected, "stage0.node")
				return converge.NodeReport{ID: "stage0.node", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "ok"}, nil
			},
		},
		&stubNode{
			id:    "stage2.node",
			stage: converge.StageBootstrapFacts,
			deps:  []string{"stage0.node"},
			inspectFn: func(_ context.Context, m converge.ObserveMode) (converge.NodeReport, error) {
				modes = append(modes, m)
				inspected = append(inspected, "stage2.node")
				return converge.NodeReport{ID: "stage2.node", Stage: converge.StageBootstrapFacts, State: converge.StateAbsent, Summary: "missing"}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}

	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(root, "", g, &stdout, &stderr)

	cmd := a.newRootCmd()
	cmd.SetArgs([]string{"status"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, ".env")); !os.IsNotExist(statErr) {
		t.Errorf("status created %s, want read-only", filepath.Join(root, ".env"))
	}
	if !strings.Contains(stdout.String(), "stage0.node") || !strings.Contains(stdout.String(), "stage2.node") {
		t.Errorf("status stdout missing node IDs:\n%s", stdout.String())
	}

	modes, inspected = nil, nil
	stdout.Reset()
	cmd = a.newRootCmd()
	cmd.SetArgs([]string{"status", "--deep", "--to", "stage-1"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("status --deep --to stage-1 error: %v", err)
	}
	if !slices.Equal(modes, []converge.ObserveMode{converge.ObserveDeep}) || !slices.Equal(inspected, []string{"stage0.node"}) {
		t.Errorf("deep filtered inspect = (modes=%v, ids=%v), want ([deep], [stage0.node])", modes, inspected)
	}
}

func TestConvergeCommandDryRunSkipsMutationAndBecomePrompt(t *testing.T) {
	executed := 0
	prompted := 0
	g, err := converge.NewGraph(
		&stubNode{
			id:             "host.selinux",
			stage:          converge.StageHostPrereqs,
			requiresBecome: true,
			inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
				return converge.NodeReport{ID: "host.selinux", Stage: converge.StageHostPrereqs, State: converge.StateAbsent, RequiresBecome: true, Summary: "missing"}, nil
			},
			convergeFn: func(context.Context, converge.ConvergeContext) error {
				executed++
				return nil
			},
		},
		&stubNode{
			id:    "host.tools",
			stage: converge.StageHostPrereqs,
			inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
				return converge.NodeReport{ID: "host.tools", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "ok"}, nil
			},
		},
	)
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}

	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(t.TempDir(), "", g, &stdout, &stderr)
	a.promptBecome = func(context.Context) (converge.BecomePassword, error) {
		prompted++
		return "example-become", nil
	}

	cmd := a.newRootCmd()
	cmd.SetArgs([]string{"converge", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("converge --dry-run error: %v", err)
	}
	if executed != 0 || prompted != 0 {
		t.Errorf("dry-run executed=%d prompted=%d, want 0/0", executed, prompted)
	}
	if !strings.Contains(stdout.String(), "host.selinux") {
		t.Errorf("dry-run output missing planned node host.selinux:\n%s", stdout.String())
	}
}

func TestConvergeCommandConfirmsAndForwardsBecomeAndAutoApprove(t *testing.T) {
	t.Run("cancels when user declines", func(t *testing.T) {
		executed := 0
		g := newSinglePlanGraph(t, "node.plan", true, func(context.Context, converge.ConvergeContext) error {
			executed++
			return nil
		})
		var stdout, stderr bytes.Buffer
		a := newTestCLIApp(t.TempDir(), "n\n", g, &stdout, &stderr)
		cmd := a.newRootCmd()
		cmd.SetArgs([]string{"converge"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("converge decline error: %v", err)
		}
		if executed != 0 {
			t.Errorf("executed = %d on declined confirm, want 0", executed)
		}
	})

	t.Run("executes after confirmation with single become prompt", func(t *testing.T) {
		var gotCtx converge.ConvergeContext
		prompted := 0
		g := newSinglePlanGraph(t, "node.plan", true, func(_ context.Context, req converge.ConvergeContext) error {
			gotCtx = req
			return nil
		})
		var stdout, stderr bytes.Buffer
		a := newTestCLIApp(t.TempDir(), "Y\n", g, &stdout, &stderr)
		a.promptBecome = func(context.Context) (converge.BecomePassword, error) {
			prompted++
			return "example-become", nil
		}

		cmd := a.newRootCmd()
		cmd.SetArgs([]string{"converge", "--auto-approve"})
		if err := cmd.Execute(); err != nil {
			t.Fatalf("converge confirmed error: %v", err)
		}
		if prompted != 1 || gotCtx.BecomePassword.Value() != "example-become" || !gotCtx.AutoApprove {
			t.Errorf("prompted=%d pw=%q autoApprove=%v, want (1, example-become, true)", prompted, gotCtx.BecomePassword.Value(), gotCtx.AutoApprove)
		}
	})
}

func TestConvergeCommandReturnsErrorWhenBlocked(t *testing.T) {
	g, err := converge.NewGraph(&stubNode{
		id:    "vault.manual_tokens",
		stage: converge.StageBootstrapFacts,
		inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
			return converge.NodeReport{
				ID:      "vault.manual_tokens",
				Stage:   converge.StageBootstrapFacts,
				State:   converge.StateBlocked,
				Summary: "missing tokens",
				Hint:    "run direnv allow",
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}

	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(t.TempDir(), "", g, &stdout, &stderr)
	cmd := a.newRootCmd()
	cmd.SetArgs([]string{"converge", "--auto-approve"})
	if err := cmd.Execute(); err == nil {
		t.Fatalf("converge expected error when blocked, got nil")
	}
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "run direnv allow") {
		t.Errorf("blocked converge output missing hint %q:\n%s", "run direnv allow", combined)
	}
}

func TestMainMenuConvergedToSixCategoriesAndSubmenus(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	got := menuLabels(a.buildMenuOptions())
	want := []string{
		"Status & Converge",
		"Host Prerequisites",
		"Bastion Vault",
		"Credentials & Registry",
		"Terraform & State Audit",
		"Quit",
	}
	if !slices.Equal(got, want) {
		t.Errorf("buildMenuOptions labels = %v, want %v", got, want)
	}
	if opts := a.buildMenuOptions(); opts[len(opts)-1].run != nil {
		t.Errorf("Quit menu item must have nil run callback")
	}

	assertSubmenuContains(t, "Host", menuLabels(a.buildHostMenuOptions()), "[Host] Apply All Workstation Prerequisites")
	assertSubmenuContains(t, "Vault", menuLabels(a.buildVaultMenuOptions()), "[Vault] Initialize Bastion Vault")
	assertSubmenuContains(t, "Credentials", menuLabels(a.buildCredentialsMenuOptions()), "[Credentials] Rotate Service Admin Passwords")
	assertSubmenuContains(t, "Terraform", menuLabels(a.buildTerraformMenuOptions()), "[Terraform] Audit State Secrets")
	if len(a.buildStatusMenuOptions()) == 0 {
		t.Errorf("buildStatusMenuOptions() returned 0 items, want non-empty")
	}
}

func TestRootCommandPreservesBackwardCompatibleSubcommands(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	rootCmd := a.newRootCmd()
	wantNames := []string{"status", "converge", "host", "vault", "credentials", "terraform", "env", "state-audit"}
	for _, name := range wantNames {
		if sub, _, err := rootCmd.Find([]string{name}); err != nil || sub == nil || sub.Name() != name {
			t.Errorf("subcommand %q missing or unresolved (sub=%v, err=%v)", name, sub, err)
		}
	}
}

func TestAppWritersDefaultToStdStreams(t *testing.T) {
	var def app
	if def.statusWriter() != os.Stdout {
		t.Errorf("default statusWriter() != os.Stdout")
	}
	if def.errWriter() != os.Stderr {
		t.Errorf("default errWriter() != os.Stderr")
	}
	var out, errBuf bytes.Buffer
	custom := app{stdout: &out, stderr: &errBuf}
	if custom.statusWriter() != &out || custom.errWriter() != &errBuf {
		t.Errorf("custom writers were not preserved")
	}
}

func newTestCLIApp(root, input string, g *converge.Graph, stdout, stderr *bytes.Buffer) *app {
	return &app{
		root:       root,
		home:       root,
		out:        ui.New(stdout, stderr),
		in:         bufio.NewReader(strings.NewReader(input)),
		stdout:     stdout,
		stderr:     stderr,
		buildGraph: func() (*converge.Graph, error) { return g, nil },
	}
}

func newSinglePlanGraph(t *testing.T, id string, requiresBecome bool, convergeFn func(context.Context, converge.ConvergeContext) error) *converge.Graph {
	t.Helper()
	g, err := converge.NewGraph(&stubNode{
		id:             id,
		stage:          converge.StageHostPrereqs,
		requiresBecome: requiresBecome,
		inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
			return converge.NodeReport{ID: id, Stage: converge.StageHostPrereqs, State: converge.StateAbsent, RequiresBecome: requiresBecome, Summary: "absent"}, nil
		},
		convergeFn: convergeFn,
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}
	return g
}

func assertSubmenuContains(t *testing.T, name string, labels []string, want string) {
	t.Helper()
	if !slices.Contains(labels, want) {
		t.Errorf("%s submenu = %v, want %q", name, labels, want)
	}
}
