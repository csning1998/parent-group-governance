package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
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

func TestFormatStatusTableWithColorPreservesAlignmentAndSummarySemantics(t *testing.T) {
	reports := []converge.NodeReport{
		{ID: "host.tools", Stage: converge.StageHostPrereqs, State: converge.StateConverged, Summary: "ok"},
		{ID: "host.env_file", Stage: converge.StageHostPrereqs, State: converge.StateAbsent, Summary: "missing"},
		{ID: "vault.unsealed", Stage: converge.StageCoreContainers, State: converge.StateDrifted, Summary: "sealed", Hint: "run unseal"},
		{ID: "vault.manual_tokens", Stage: converge.StageBootstrapFacts, State: converge.StateBlocked, Summary: "blocked"},
	}

	var buf bytes.Buffer
	formatStatusTableWithColor(&buf, reports, true)
	out := buf.String()

	for _, want := range []string{
		ui.Colorize(ui.Step, "Stage 0: Host Prerequisites", true),
		ui.Colorize(ui.OK, "CONVERGED ", true),
		ui.Colorize(ui.Task, "ABSENT    ", true),
		ui.Colorize(ui.Warn, "DRIFTED   ", true),
		ui.Colorize(ui.Error, "BLOCKED   ", true),
		ui.Colorize(ui.Warn, "hint: run unseal", true),
		ui.Colorize(ui.OK, "1 CONVERGED", true),
		ui.Colorize(ui.Error, "1 BLOCKED", true),
	} {
		if !strings.Contains(out, want) {
			t.Errorf("colored status table missing %q:\n%q", want, out)
		}
	}

	buf.Reset()
	formatStatusTableWithColor(&buf, reports[:1], true)
	summaryOnly := buf.String()
	if strings.Contains(summaryOnly, "\033[0;31m0 BLOCKED") {
		t.Errorf("zero BLOCKED count should not be red-colored: %q", summaryOnly)
	}
	if stateColorLevel(converge.NodeState("UNKNOWN")) != ui.Info {
		t.Errorf("stateColorLevel(UNKNOWN) != ui.Info")
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
		assertProbeState(t, a.inspectHostVaultAudit, converge.StateDrifted)

		writeExecutable(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\necho masked\nexit 1\n")
		assertProbeState(t, a.inspectHostVaultAudit, converge.StateDrifted)

		writeExecutable(t, filepath.Join(bin, "systemctl"), "#!/bin/sh\nexit 1\n")
		assertProbeState(t, a.inspectHostVaultAudit, converge.StateAbsent)
		_, _, _ = a.inspectHostTelemetry(context.Background(), converge.ObserveFast)
	})
}

func TestDeepFlagHelpMatchesObservedBehavior(t *testing.T) {
	var stdout, stderr bytes.Buffer
	a := newTestCLIApp(t.TempDir(), "", nil, &stdout, &stderr)
	rootCmd := a.newRootCmd()

	for _, name := range []string{"status", "converge"} {
		sub, _, err := rootCmd.Find([]string{name})
		if err != nil || sub == nil {
			t.Fatalf("Find(%q): sub=%v err=%v", name, sub, err)
		}
		flag := sub.Flags().Lookup("deep")
		if flag == nil {
			t.Fatalf("%s missing --deep flag", name)
		}
		if !strings.Contains(flag.Usage, "terraform plan") {
			t.Errorf("%s --deep usage = %q, want mention of terraform plan", name, flag.Usage)
		}
		if strings.Contains(flag.Usage, "Ansible --check") {
			t.Errorf("%s --deep usage = %q, still falsely claims Ansible --check", name, flag.Usage)
		}
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
