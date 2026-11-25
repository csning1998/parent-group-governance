package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
)

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

func TestConvergeRotateSonarQubeAdminRejectsEmptyKey(t *testing.T) {
	a := &app{
		credentials: []credentials.Credential{{Key: "unrelated-service-password"}},
	}
	err := a.convergeRotateSonarQubeAdmin(context.Background(), converge.ConvergeContext{})
	if err == nil || !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("convergeRotateSonarQubeAdmin error = %v, want not configured error", err)
	}
}

func TestConvergeCommandLoadsExistingEnvReadOnly(t *testing.T) {
	g, err := converge.NewGraph(&stubNode{
		id:    "host.tools",
		stage: converge.StageHostPrereqs,
		inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
			return converge.NodeReport{ID: "host.tools", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "ok"}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewGraph: %v", err)
	}

	root := t.TempDir()
	writePlainFile(t, filepath.Join(root, ".env"), "COMPOSE_PROJECT_NAME=example-gov\n")
	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(root, "", g, &stdout, &stderr)
	cmd := a.newRootCmd()
	cmd.SetArgs([]string{"converge", "--dry-run"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("converge --dry-run error: %v", err)
	}
	if a.env == nil || a.env.Get("COMPOSE_PROJECT_NAME") != "example-gov" {
		t.Errorf("a.env after converge = %v, want COMPOSE_PROJECT_NAME=example-gov", a.env)
	}

	emptyRoot := t.TempDir()
	emptyApp := newTestCLIApp(emptyRoot, "", g, &stdout, &stderr)
	emptyCmd := emptyApp.newRootCmd()
	emptyCmd.SetArgs([]string{"converge", "--dry-run"})
	if err := emptyCmd.Execute(); err != nil {
		t.Fatalf("converge --dry-run without .env error: %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(emptyRoot, ".env")); !os.IsNotExist(statErr) {
		t.Errorf("converge --dry-run created %s, want read-only when .env missing", filepath.Join(emptyRoot, ".env"))
	}
}

func TestNestedSubcommandNamedStatusStillBootstrapsEnv(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(t.TempDir(), "", nil, &stdout, &stderr)
	rootCmd := a.newRootCmd()
	hostCmd, _, err := rootCmd.Find([]string{"host"})
	if err != nil {
		t.Fatalf("Find(host): %v", err)
	}
	hostCmd.AddCommand(&cobra.Command{
		Use:  "status",
		RunE: func(*cobra.Command, []string) error { return nil },
	})
	rootCmd.SetArgs([]string{"host", "status"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("host status error: %v", err)
	}
	if a.env == nil {
		t.Errorf("a.env = nil for nested host status subcommand, want Bootstrapped env")
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

func TestWorkstationGraphWiringAndConvergeHelpers(t *testing.T) {
	f := newHostFixture(t, "example-become", "")
	writeExecutable(t, filepath.Join(filepath.Dir(f.log), "podman"), "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then echo '[]'; else echo up; fi\n")
	t.Setenv("PATH", filepath.Dir(f.log)+string(os.PathListSeparator)+os.Getenv("PATH"))

	f.a.stdout, f.a.stderr = io.Discard, io.Discard
	graph, err := f.a.resolveWorkstationGraph()
	if err != nil || len(graph.Order()) != 27 {
		t.Fatalf("resolveWorkstationGraph = (%d nodes, %v), want 27 nodes", len(graph.Order()), err)
	}
	if got := stageLabel(converge.Stage(99)); got != "Stage 99" {
		t.Errorf("stageLabel(99) = %q, want Stage 99", got)
	}

	var buf bytes.Buffer
	a := &app{out: ui.New(&buf, &buf), in: bufio.NewReader(strings.NewReader("example-become\n\n")), stdout: &buf, stderr: &buf}
	a.printDryRunPlan(nil)
	if err := handleNoPlannedNodes(&buf, nil); err != nil {
		t.Fatalf("handleNoPlannedNodes(nil): %v", err)
	}
	pw, err := a.promptBecomePassword(context.Background())
	if err != nil || pw.Value() != "example-become" {
		t.Fatalf("promptBecomePassword = (%q, %v), want example-become", pw.Value(), err)
	}
	if _, err := a.promptBecomePassword(context.Background()); err == nil {
		t.Errorf("empty promptBecomePassword expected error")
	}

	req := converge.ConvergeContext{BecomePassword: "example-become"}
	if err := f.a.runSELinuxStep(context.Background(), req); err != nil {
		t.Errorf("runSELinuxStep: %v", err)
	}
	if err := f.a.runLibvirtStep(context.Background(), req); err != nil {
		t.Errorf("runLibvirtStep: %v", err)
	}
	if err := f.a.runVaultProxyStep(context.Background(), req); err != nil {
		t.Errorf("runVaultProxyStep: %v", err)
	}
	if err := f.a.startCoreContainers(context.Background(), req); err != nil {
		t.Errorf("startCoreContainers: %v", err)
	}
	if _, err := converge.Observe(context.Background(), graph, converge.ObserveFast, ""); err != nil {
		t.Errorf("Observe(real graph): %v", err)
	}
	if err := f.a.convergeRotateSonarQubeAdmin(context.Background(), req); err == nil {
		t.Errorf("convergeRotateSonarQubeAdmin expected error when unregistered")
	}
}

func TestSubmenuBackAndEmptyCredentialsMenu(t *testing.T) {
	var buf bytes.Buffer
	a := &app{
		root:   t.TempDir(),
		home:   t.TempDir(),
		out:    ui.New(&buf, &buf),
		in:     bufio.NewReader(strings.NewReader("bad\n2\n6\n")),
		stdout: &buf,
		stderr: &buf,
	}
	a.topology = topology.VaultTopology{BastionVault: topology.BastionVault{LoopbackIP: "127.0.0.1", PublishIP: "192.0.2.10", APIPort: 8200}}
	err := a.runSubmenu(context.Background(), "Test", []menuOption{
		{label: "Act", run: func(context.Context) error { return nil }},
		{label: "Back", run: nil},
	})
	if err == nil || err.Error() != msgMenuBack {
		t.Fatalf("runSubmenu Back = %v, want %q", err, msgMenuBack)
	}

	a.in = bufio.NewReader(strings.NewReader("5\n2\n6\n"))
	if err := a.runMenu(context.Background()); err != nil {
		t.Fatalf("runMenu Back->Quit: %v", err)
	}
	if err := a.runRotateCredentialMenu(context.Background()); err != nil {
		t.Fatalf("runRotateCredentialMenu empty: %v", err)
	}
	if err := a.runReconcileCredentialMenu(context.Background()); err != nil {
		t.Fatalf("runReconcileCredentialMenu empty: %v", err)
	}
}

func TestWorkstationDepsClosuresAndConvergeBranches(t *testing.T) {
	f := newHostFixture(t, "example-become", "")
	writeExecutable(t, filepath.Join(filepath.Dir(f.log), "podman"), "#!/bin/sh\nif [ \"$1\" = \"ps\" ]; then echo '[]'; else echo up; fi\n")
	t.Setenv("PATH", filepath.Dir(f.log)+string(os.PathListSeparator)+os.Getenv("PATH"))
	f.a.stdout, f.a.stderr = io.Discard, io.Discard

	deps := f.a.buildWorkstationDeps()
	ctx := context.Background()
	req := converge.ConvergeContext{BecomePassword: "example-become"}
	_ = deps.Host.BootstrapEnv(ctx, req)
	for _, fn := range []func(context.Context, converge.ConvergeContext) error{
		deps.Host.ApplySELinux,
		deps.Host.EnsureTLSCA,
		deps.Host.ApplyLibvirt,
		deps.Host.ApplyVaultProxy,
		deps.Host.ApplyVaultAudit,
		deps.Host.ApplyTelemetry,
		deps.Vault.InitVault,
		deps.Vault.UnsealVault,
		deps.Vault.EnableKVSecret,
		deps.Vault.RevokeRootToken,
		deps.Credentials.RegisterGitLabGroupRunner,
		deps.Credentials.IssueSonarQubeAnalysisToken,
		deps.Credentials.PublishCodeReviewerVariables,
	} {
		_ = fn(ctx, req)
	}
	_ = deps.Vault.InspectSealStatus(ctx)
	_, _, _ = deps.Vault.VerifyFactoryDefault(ctx)
	_ = f.a.runTelemetrySteps(ctx, req)

	gConverged, err := converge.NewGraph(&stubNode{
		id:    "node.ok",
		stage: converge.StageHostPrereqs,
		inspectFn: func(context.Context, converge.ObserveMode) (converge.NodeReport, error) {
			return converge.NodeReport{ID: "node.ok", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "ok"}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	convApp := newTestCLIApp(t.TempDir(), "", gConverged, &out, &out)
	if err := convApp.runConverge(ctx, convergeFlags{deep: true}); err != nil {
		t.Errorf("runConverge(all converged): %v", err)
	}
	convApp.printDryRunPlan(nil)
}

func TestMenuCallbacksWithPopulatedConfig(t *testing.T) {
	vaultSrv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, vaultSrv, "example-token")
	a.in = bufio.NewReader(strings.NewReader("2\n"))
	a.stdout, a.stderr = io.Discard, io.Discard
	a.resolveOrigin = func(context.Context) (gitlabOrigin, error) { return gitlabOrigin{}, errors.New("offline") }
	a.buildGraph = func() (*converge.Graph, error) { return nil, errors.New("example graph error") }
	a.issuedTokens = issuedtokens.Config{
		SonarQubeAnalysisToken: issuedtokens.SonarQubeAnalysisTokenConfig{UserTokensEndpoint: "http://127.0.0.1:1/u"},
		GitLabGroupRunner:      issuedtokens.GitLabGroupRunnerConfig{ConfigPath: "gitlab-runner-configs/config.toml"},
		CodeReviewerVariables:  issuedtokens.CodeReviewerVariablesConfig{BotTokens: []issuedtokens.ReviewerBotToken{{VariableKeys: []string{"K"}}}},
	}
	a.topology.OperatorVaultProxy.UserConfigDir = ".config/vault-proxy"
	a.topology.OperatorVaultProxy.Identities = map[string]topology.ProxyIdentity{
		"administrator": {ListenPort: a.topology.BastionVault.APIPort},
	}
	caPEM, err := os.ReadFile(filepath.Join(a.root, "vault", "tls", "ca-ml-dsa-87.pem"))
	if err != nil {
		t.Fatal(err)
	}
	writePlainFile(t, filepath.Join(a.home, ".config", "vault-proxy", "ca.pem"), string(caPEM))
	writePlainFile(t, filepath.Join(a.home, ".config", "vault-proxy", "administrator", "client.pem"), string(caPEM))
	writePlainFile(t, filepath.Join(a.home, ".config", "vault-proxy", "administrator", "client-key.pem"), "key")

	ctx := context.Background()
	_, _ = a.verifyAdminProxy(ctx)
	_, _ = a.newObserveVaultClient(ctx)
	_ = a.convergeRevokeRootToken(ctx, converge.ConvergeContext{})

	for _, opt := range a.buildMenuOptions() {
		if opt.run != nil {
			a.in = bufio.NewReader(strings.NewReader("9\n5\n8\n7\n3\n2\n"))
			_ = opt.run(ctx)
		}
	}

	for _, list := range [][]menuOption{
		a.buildStatusMenuOptions(),
		a.buildVaultMenuOptions(),
		a.buildCredentialsMenuOptions(),
		a.buildTerraformMenuOptions(),
	} {
		for _, opt := range list {
			if opt.run != nil {
				_ = opt.run(ctx)
			}
		}
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
