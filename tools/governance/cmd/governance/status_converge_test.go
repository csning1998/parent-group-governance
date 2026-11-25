package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/issuedtokens"
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

func TestInspectPodmanContainersAndState(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\ncat <<'EOF'\n" +
		`[{"Names":["example-healthy"],"State":"running","Status":"Up 1 hour (healthy)"},{"Names":["example-sick"],"State":"running","Status":"Up 1 minute (unhealthy)"},{"Names":[],"State":"exited","Status":"Exited (0)"}]` +
		"\nEOF\n"
	writeExecutable(t, filepath.Join(bin, "podman"), script)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	states, err := inspectPodmanContainers(context.Background())
	if err != nil {
		t.Fatalf("inspectPodmanContainers: %v", err)
	}
	want := []converge.ContainerState{
		{Name: "example-healthy", Running: true, Healthy: true},
		{Name: "example-sick", Running: true, Healthy: false},
		{Name: "", Running: false, Healthy: false},
	}
	if !slices.Equal(states, want) {
		t.Errorf("states = %+v, want %+v", states, want)
	}
}

func TestHostLocalProbes(t *testing.T) {
	t.Run("selinux probe classifies context", func(t *testing.T) {
		root := t.TempDir()
		writeExecutable(t, filepath.Join(root, "bin", "ls"), "#!/bin/sh\necho 'unconfined_u:object_r:container_file_t:s0 /tmp/x'\n")
		t.Setenv("PATH", filepath.Join(root, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
		a := &app{root: root}
		assertProbeState(t, a.inspectHostSELinux, converge.StateConverged)

		writeExecutable(t, filepath.Join(root, "bin", "ls"), "#!/bin/sh\necho 'unconfined_u:object_r:user_home_t:s0 /tmp/x'\n")
		assertProbeState(t, a.inspectHostSELinux, converge.StateDrifted)

		writeExecutable(t, filepath.Join(root, "bin", "ls"), "#!/bin/sh\nexit 2\n")
		assertProbeState(t, a.inspectHostSELinux, converge.StateAbsent)
	})

	t.Run("libvirt probe classifies rendered configs", func(t *testing.T) {
		root := t.TempDir()
		a := &app{root: root}
		assertProbeState(t, a.inspectHostLibvirt, converge.StateAbsent)

		writePlainFile(t, filepath.Join(root, renderedLibvirtFiles[0]), "x")
		assertProbeState(t, a.inspectHostLibvirt, converge.StateDrifted)

		for _, rel := range renderedLibvirtFiles[1:] {
			writePlainFile(t, filepath.Join(root, rel), "x")
		}
		assertProbeState(t, a.inspectHostLibvirt, converge.StateConverged)
	})

	t.Run("vault proxy and audit systemd probes", func(t *testing.T) {
		root, bin := t.TempDir(), t.TempDir()
		writeExecutable(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\nif [ \"$2\" = \"is-enabled\" ]; then echo enabled; fi\nexit 0\n")
		t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

		a := &app{
			root: root,
			home: root,
			topology: topology.VaultTopology{OperatorVaultProxy: topology.OperatorVaultProxy{
				UserConfigDir: ".config/vault-proxy",
				Identities:    map[string]topology.ProxyIdentity{"administrator": {ListenPort: 8212}},
			}},
		}
		assertProbeState(t, a.inspectHostVaultProxy, converge.StateAbsent)
		writePlainFile(t, filepath.Join(root, ".config", "vault-proxy", "ca.pem"), "ca")
		assertProbeState(t, a.inspectHostVaultProxy, converge.StateDrifted)
		writePlainFile(t, filepath.Join(root, ".config", "vault-proxy", "administrator", "client.pem"), "cert")
		assertProbeState(t, a.inspectHostVaultProxy, converge.StateConverged)
		assertProbeState(t, a.inspectHostVaultAudit, converge.StateConverged)

		writeExecutable(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\necho disabled\nexit 1\n")
		assertProbeState(t, a.inspectHostVaultProxy, converge.StateDrifted)
		assertProbeState(t, a.inspectHostVaultAudit, converge.StateAbsent)
		_, _, _ = a.inspectHostTelemetry(context.Background(), converge.ObserveFast)
	})
}

func TestObserveVaultMountAndKVProbes(t *testing.T) {
	srv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, srv, "example-root-token")
	ctx := context.Background()

	secretMounted, err := a.hasSecretMount(ctx)
	if err != nil || !secretMounted {
		t.Fatalf("hasSecretMount = (%t, %v), want (true, nil)", secretMounted, err)
	}
	certMounted, err := a.hasOperatorCertMount(ctx)
	if err != nil || !certMounted {
		t.Fatalf("hasOperatorCertMount = (%t, %v), want (true, nil)", certMounted, err)
	}
	if err := a.writeVaultKVMap(ctx, "secret", "example/path", map[string]string{"k": "v"}); err != nil {
		t.Fatalf("writeVaultKVMap: %v", err)
	}
	got, found, err := a.readVaultKVMap(ctx, "secret", "example/path")
	if err != nil || !found || got["k"] != "v" {
		t.Fatalf("readVaultKVMap(existing) = (%v, %t, %v), want k=v", got, found, err)
	}
	if _, missing, err := a.readVaultKVMap(ctx, "secret", "missing/path"); err != nil || missing {
		t.Fatalf("readVaultKVMap(missing) = (%t, %v), want (false, nil)", missing, err)
	}
	if active, err := a.verifyAdminProxy(ctx); err != nil || active {
		t.Fatalf("verifyAdminProxy without proxy cfg = (%t, %v), want (false, nil)", active, err)
	}
}

func TestObserveVaultSonarQubeCredentialProbes(t *testing.T) {
	srv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, srv, "example-root-token")
	ctx := context.Background()

	sonarSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pw, _ := r.BasicAuth()
		if pw == "example-rotated" {
			_, _ = w.Write([]byte(`{"valid":true}`))
			return
		}
		_, _ = w.Write([]byte(`{"valid":false}`))
	}))
	t.Cleanup(sonarSrv.Close)

	a.credentials = loadExampleCredential(t, sonarSrv.URL+"/api/authentication/validate")
	a.issuedTokens.SonarQubeAnalysisToken.AdminPasswordKey = "sonarqube-admin-password"
	_ = a.writeVaultKVMap(ctx, "secret", "parent-group-governance/sonarqube/admin-account", map[string]string{"sonarqube_admin_password": "example-rotated"})

	fresh, retained, err := a.verifyFactoryDefault(ctx)
	if err != nil || fresh || retained != "sonarqube-admin-password" {
		t.Fatalf("verifyFactoryDefault = (%t, %q, %v), want (false, sonarqube-admin-password, nil)", fresh, retained, err)
	}
	ok, err := a.verifySonarQubeAdmin(ctx)
	if err != nil || !ok {
		t.Fatalf("verifySonarQubeAdmin = (%t, %v), want (true, nil)", ok, err)
	}
}

func TestObserveGitLabProbes(t *testing.T) {
	vaultSrv := newFakeObserveVaultServer(t)
	a := newFakeVaultApp(t, vaultSrv, "example-root-token")
	ctx := context.Background()

	gitlabSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.EscapedPath() {
		case "/api/v4/projects/example-group%2Fparent-group-governance",
			"/api/v4/groups/42/variables/SONAR_HOST_URL",
			"/api/v4/groups/42/variables/SONAR_TOKEN",
			"/api/v4/projects/example-group%2Fexample-app/variables/TAG_PUSH_TOKEN":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(gitlabSrv.Close)

	a.resolveOrigin = func(context.Context) (gitlabOrigin, error) {
		return gitlabOrigin{WebURL: gitlabSrv.URL, APIURL: gitlabSrv.URL + "/api/v4", TopLevelGroup: "example-group"}, nil
	}
	a.topology.OperatorVaultProxy.StateBackend = topology.StateBackend{VaultKVMount: "secret", VaultKVField: "token"}
	a.topology.OperatorVaultProxy.Identities = map[string]topology.ProxyIdentity{
		"credential-distributor-parent-group-governance": {CodeReviewerVariableProjects: []string{"example-app"}},
	}
	a.issuedTokens = issuedtokens.Config{
		GitLabGroupRegistry: issuedtokens.VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "group_id"},
		CodeReviewerVariables: issuedtokens.CodeReviewerVariablesConfig{
			BotTokens: []issuedtokens.ReviewerBotToken{{VariableKeys: []string{"TAG_PUSH_TOKEN"}}},
		},
	}

	_ = a.writeVaultKVMap(ctx, "secret", "parent-group-governance/terraform/state-backend", map[string]string{"token": "pat"})
	_ = a.writeVaultKVMap(ctx, "registry", "platform/gitlab-group/top-level", map[string]string{"group_id": "42"})

	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "administration-gitlab-project")); err != nil || !applied {
		t.Fatalf("inspectGitLabLayerApplied(admin) = (%t, %v), want (true, nil)", applied, err)
	}
	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "group-gitlab-configuration")); err != nil || !applied {
		t.Fatalf("inspectGitLabLayerApplied(config) = (%t, %v), want (true, nil)", applied, err)
	}
	if applied, err := a.inspectGitLabLayerApplied(ctx, filepath.Join(a.root, "terraform", "layers", "other")); err != nil || applied {
		t.Fatalf("inspectGitLabLayerApplied(other) = (%t, %v), want (false, nil)", applied, err)
	}
	if hasVar, err := a.verifyGroupVariable(ctx, "SONAR_TOKEN"); err != nil || !hasVar {
		t.Fatalf("verifyGroupVariable = (%t, %v), want (true, nil)", hasVar, err)
	}
	if present, total, err := a.verifyProjectVariables(ctx); err != nil || present != 1 || total != 1 {
		t.Fatalf("verifyProjectVariables = (%d, %d, %v), want (1, 1, nil)", present, total, err)
	}

	noTokenApp := newFakeVaultApp(t, vaultSrv, "")
	noTokenApp.resolveOrigin = a.resolveOrigin
	noTokenApp.topology.OperatorVaultProxy.Identities = a.topology.OperatorVaultProxy.Identities
	noTokenApp.issuedTokens = a.issuedTokens
	if present, total, err := noTokenApp.verifyProjectVariables(ctx); err != nil || present != 0 || total != 1 {
		t.Fatalf("verifyProjectVariables(no vault) = (%d, %d, %v), want (0, 1, nil)", present, total, err)
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

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	writePlainFile(t, path, content)
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
}

func writePlainFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertProbeState(t *testing.T, fn func(context.Context, converge.ObserveMode) (converge.NodeState, string, error), want converge.NodeState) {
	t.Helper()
	got, _, err := fn(context.Background(), converge.ObserveFast)
	if err != nil || got != want {
		t.Fatalf("probe state = (%q, %v), want %q", got, err, want)
	}
}

func newFakeObserveVaultServer(t *testing.T) *httptest.Server {
	t.Helper()
	kv := make(map[string]map[string]any)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/mounts":
			_, _ = w.Write([]byte(`{"data":{"secret/":{"type":"kv"}}}`))
		case r.URL.Path == "/v1/sys/auth":
			_, _ = w.Write([]byte(`{"data":{"operator-cert/":{"type":"cert"}}}`))
		case strings.Contains(r.URL.Path, "/data/") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			var body struct {
				Data map[string]any `json:"data"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			kv[r.URL.Path] = body.Data
			_, _ = w.Write([]byte(`{"data":{"version":1}}`))
		case strings.Contains(r.URL.Path, "/data/") && r.Method == http.MethodGet:
			data, ok := kv[r.URL.Path]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"data": data, "metadata": map[string]any{"version": 1}}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newFakeVaultApp(t *testing.T, srv *httptest.Server, token string) *app {
	t.Helper()
	root, home := t.TempDir(), t.TempDir()
	_, portStr, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	port, _ := strconv.Atoi(portStr)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	writePlainFile(t, filepath.Join(root, "vault", "tls", "ca-ml-dsa-87.pem"), string(caPEM))
	writePlainFile(t, filepath.Join(home, ".vault-token"), token)
	return &app{
		root: root,
		home: home,
		topology: topology.VaultTopology{
			BastionVault:       topology.BastionVault{LoopbackIP: "127.0.0.1", PublishIP: "192.0.2.10", APIPort: port},
			OperatorVaultProxy: topology.OperatorVaultProxy{GovernanceOwnerCode: "parent-group-governance", CertAuthMount: "operator-cert"},
		},
		out: ui.New(io.Discard, io.Discard),
	}
}

func loadExampleCredential(t *testing.T, verifyURL string) []credentials.Credential {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "topo.yaml")
	writePlainFile(t, cfgPath, "service_admin_passwords:\n  - key: sonarqube-admin-password\n    vault_kv_mount: secret\n    vault_kv_path: parent-group-governance/sonarqube/admin-account\n    length: 24\n    service:\n      mechanism: http_form\n      rotate_endpoint: "+verifyURL+"\n      verify_endpoint: "+verifyURL+"\n      admin_username: admin\n      factory_default_password: admin\n")
	cfg, err := credentials.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatal(err)
	}
	return creds
}
