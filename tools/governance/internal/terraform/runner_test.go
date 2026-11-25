package terraform

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type verifyDirenvCase struct {
	name       string
	statusJSON string
	statusExit string
	wantOK     bool
	wantPath   string
	wantErr    bool
}

type planLayerCase struct {
	name          string
	bootstrapRoot bool
	execExit      string
	wantOutcome   PlanOutcome
	wantErr       bool
	wantIdentity  string
}

type applyLayerCase struct {
	name          string
	bootstrapRoot bool
	autoApprove   bool
	execExit      string
	wantCmd       string
	wantErr       bool
	wantIdentity  string
}

func TestVerifyDirenvAllowedParsesStatusJSON(t *testing.T) {
	cases := []verifyDirenvCase{
		{
			name:       "approved envrc",
			statusJSON: `{"state":{"foundRC":{"allowed":0,"path":"/tmp/example-layer/.envrc"}}}`,
			wantOK:     true,
			wantPath:   "/tmp/example-layer/.envrc",
		},
		{
			name:       "unapproved envrc",
			statusJSON: `{"state":{"foundRC":{"allowed":1,"path":"/tmp/example-layer/.envrc"}}}`,
			wantOK:     false,
			wantPath:   "/tmp/example-layer/.envrc",
		},
		{
			name:       "missing envrc",
			statusJSON: `{"state":{"foundRC":null}}`,
			wantOK:     false,
			wantPath:   "",
		},
		{
			name:       "malformed JSON",
			statusJSON: `{not-json`,
			wantErr:    true,
		},
		{
			name:       "non-zero exit",
			statusJSON: `{}`,
			statusExit: "2",
			wantErr:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runVerifyDirenvCase(t, tc)
		})
	}
}

func TestPlanLayerRejectsUnapprovedDirenv(t *testing.T) {
	layerDir := t.TempDir()
	logPath := setupFakeDirenv(t, `{"state":{"foundRC":{"allowed":1,"path":"`+filepath.Join(layerDir, ".envrc")+`"}}}`, "0", "0")

	_, err := PlanLayer(context.Background(), RunRequest{LayerDir: layerDir})
	if !errors.Is(err, ErrDirenvNotAllowed) {
		t.Fatalf("PlanLayer error = %v, want errors.Is(_, ErrDirenvNotAllowed)", err)
	}
	assertNoExecCalls(t, logPath)
}

func TestPlanLayerInterpretsExitCodesAndEnv(t *testing.T) {
	cases := []planLayerCase{
		{
			name:          "converged exit 0 without bootstrap root",
			bootstrapRoot: false,
			execExit:      "0",
			wantOutcome:   PlanConverged,
			wantIdentity:  "__UNSET__",
		},
		{
			name:          "drifted exit 2 with bootstrap root",
			bootstrapRoot: true,
			execExit:      "2",
			wantOutcome:   PlanDrifted,
			wantIdentity:  "root",
		},
		{
			name:          "failed exit 1",
			bootstrapRoot: false,
			execExit:      "1",
			wantErr:       true,
			wantIdentity:  "__UNSET__",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runPlanLayerCase(t, tc)
		})
	}
}

func TestApplyLayerRejectsUnapprovedDirenv(t *testing.T) {
	layerDir := t.TempDir()
	logPath := setupFakeDirenv(t, `{"state":{"foundRC":{"allowed":1,"path":"`+filepath.Join(layerDir, ".envrc")+`"}}}`, "0", "0")

	err := ApplyLayer(context.Background(), RunRequest{LayerDir: layerDir})
	if !errors.Is(err, ErrDirenvNotAllowed) {
		t.Fatalf("ApplyLayer error = %v, want errors.Is(_, ErrDirenvNotAllowed)", err)
	}
	assertNoExecCalls(t, logPath)
}

func TestApplyLayerRunsDirenvExecWithFlagsAndIdentity(t *testing.T) {
	cases := []applyLayerCase{
		{
			name:          "interactive apply without bootstrap root",
			bootstrapRoot: false,
			autoApprove:   false,
			execExit:      "0",
			wantCmd:       terraformApplyShellCommand,
			wantIdentity:  "__UNSET__",
		},
		{
			name:          "auto-approve apply with bootstrap root",
			bootstrapRoot: true,
			autoApprove:   true,
			execExit:      "0",
			wantCmd:       terraformApplyAutoApproveShellCommand,
			wantIdentity:  "root",
		},
		{
			name:          "non-zero exit propagates error",
			bootstrapRoot: false,
			autoApprove:   true,
			execExit:      "1",
			wantCmd:       terraformApplyAutoApproveShellCommand,
			wantErr:       true,
			wantIdentity:  "__UNSET__",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runApplyLayerCase(t, tc)
		})
	}
}

func TestPlanLayerIncludesStderrWhenUnbuffered(t *testing.T) {
	layerDir := t.TempDir()
	statusJSON := `{"state":{"foundRC":{"allowed":0,"path":"` + filepath.Join(layerDir, ".envrc") + `"}}}`
	_ = setupFakeDirenv(t, statusJSON, "0", "1")
	t.Setenv("FAKE_DIRENV_EXEC_STDERR", "Error: No configuration files")

	_, err := PlanLayer(context.Background(), RunRequest{LayerDir: layerDir})
	if err == nil || !strings.Contains(err.Error(), "Error: No configuration files") {
		t.Fatalf("PlanLayer error = %v, want stderr message included", err)
	}
}

func TestPlanLayerCancellationKillsProcessGroup(t *testing.T) {
	layerDir := t.TempDir()
	statusJSON := `{"state":{"foundRC":{"allowed":0,"path":"` + filepath.Join(layerDir, ".envrc") + `"}}}`
	_ = setupFakeDirenv(t, statusJSON, "0", "0")
	t.Setenv("FAKE_DIRENV_EXEC_SLEEP", "3")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	var stdout, stderr bytes.Buffer
	start := time.Now()
	_, err := PlanLayer(ctx, RunRequest{
		LayerDir: layerDir,
		Stdout:   &stdout,
		Stderr:   &stderr,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("PlanLayer after timeout expected error, got nil")
	}
	if elapsed >= 1500*time.Millisecond {
		t.Fatalf("PlanLayer took %s after context timeout, orphaned child held pipe open", elapsed)
	}
}

func TestApplyLayerInteractiveKeepsForegroundProcessGroup(t *testing.T) {
	layerDir := t.TempDir()
	statusJSON := `{"state":{"foundRC":{"allowed":0,"path":"` + filepath.Join(layerDir, ".envrc") + `"}}}`
	_ = setupFakeDirenv(t, statusJSON, "0", "0")
	pgidFile := filepath.Join(t.TempDir(), "pgid")
	t.Setenv("FAKE_DIRENV_PGID_FILE", pgidFile)

	var stdout, stderr bytes.Buffer
	err := ApplyLayer(context.Background(), RunRequest{
		LayerDir:    layerDir,
		AutoApprove: false,
		Stdin:       strings.NewReader("yes\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
	})
	if err != nil {
		t.Fatalf("ApplyLayer interactive error: %v", err)
	}
	raw, readErr := os.ReadFile(pgidFile)
	if readErr != nil {
		t.Fatalf("read pgidFile: %v", readErr)
	}
	wantPGID := strconv.Itoa(syscall.Getpgrp())
	if got := strings.TrimSpace(string(raw)); got != wantPGID {
		t.Fatalf("interactive child pgid = %q, want parent foreground pgid %q", got, wantPGID)
	}
}

func runVerifyDirenvCase(t *testing.T, tc verifyDirenvCase) {
	t.Helper()
	layerDir := t.TempDir()
	logPath := setupFakeDirenv(t, tc.statusJSON, tc.statusExit, "0")

	ok, rcPath, err := VerifyDirenvAllowed(context.Background(), layerDir)
	assertErrState(t, "VerifyDirenvAllowed", err, tc.wantErr)
	assertSingleStatusCall(t, logPath, layerDir)
	if !tc.wantErr && (ok != tc.wantOK || rcPath != tc.wantPath) {
		t.Errorf("VerifyDirenvAllowed = (%v, %q), want (%v, %q)", ok, rcPath, tc.wantOK, tc.wantPath)
	}
}

func runPlanLayerCase(t *testing.T, tc planLayerCase) {
	t.Helper()
	layerDir := t.TempDir()
	statusJSON := `{"state":{"foundRC":{"allowed":0,"path":"` + filepath.Join(layerDir, ".envrc") + `"}}}`
	logPath := setupFakeDirenv(t, statusJSON, "0", tc.execExit)

	var stdout, stderr bytes.Buffer
	outcome, err := PlanLayer(context.Background(), RunRequest{
		LayerDir:              layerDir,
		BootstrapRootIdentity: tc.bootstrapRoot,
		Stdout:                &stdout,
		Stderr:                &stderr,
	})
	assertErrState(t, "PlanLayer", err, tc.wantErr)
	if !tc.wantErr && outcome != tc.wantOutcome {
		t.Errorf("PlanLayer outcome = %q, want %q", outcome, tc.wantOutcome)
	}
	assertSingleExecCall(t, logPath, layerDir, terraformPlanShellCommand, tc.wantIdentity)
}

func runApplyLayerCase(t *testing.T, tc applyLayerCase) {
	t.Helper()
	layerDir := t.TempDir()
	statusJSON := `{"state":{"foundRC":{"allowed":0,"path":"` + filepath.Join(layerDir, ".envrc") + `"}}}`
	logPath := setupFakeDirenv(t, statusJSON, "0", tc.execExit)

	var stdout, stderr bytes.Buffer
	err := ApplyLayer(context.Background(), RunRequest{
		LayerDir:              layerDir,
		BootstrapRootIdentity: tc.bootstrapRoot,
		AutoApprove:           tc.autoApprove,
		Stdin:                 strings.NewReader(""),
		Stdout:                &stdout,
		Stderr:                &stderr,
	})
	assertErrState(t, "ApplyLayer", err, tc.wantErr)
	assertSingleExecCall(t, logPath, layerDir, tc.wantCmd, tc.wantIdentity)
}

func setupFakeDirenv(t *testing.T, statusJSON, statusExit, execExit string) string {
	t.Helper()
	binDir := t.TempDir()
	logPath := filepath.Join(binDir, "direnv.log")
	scriptPath := filepath.Join(binDir, direnvBinary)

	const fakeDirenvScript = `#!/bin/sh
set -eu
subcommand="${1:-}"
if [ "${subcommand}" = "status" ]; then
  printf 'status\t%s\t%s\n' "$(pwd)" "$*" >> "${FAKE_DIRENV_LOG}"
  printf '%s\n' "${FAKE_DIRENV_STATUS_JSON:-}"
  exit "${FAKE_DIRENV_STATUS_EXIT:-0}"
fi
if [ "${subcommand}" = "exec" ]; then
  printf 'exec\t%s\t%s\t%s\t%s\t%s\t%s\n' "$(pwd)" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${VAULT_PROXY_IDENTITY-__UNSET__}" >> "${FAKE_DIRENV_LOG}"
  if [ -n "${FAKE_DIRENV_PGID_FILE:-}" ]; then
    ps -o pgid= -p "$$" | tr -d ' ' > "${FAKE_DIRENV_PGID_FILE}"
  fi
  if [ -n "${FAKE_DIRENV_EXEC_STDERR:-}" ]; then
    printf '%s\n' "${FAKE_DIRENV_EXEC_STDERR}" >&2
  fi
  if [ -n "${FAKE_DIRENV_EXEC_SLEEP:-}" ]; then
    /bin/sh -c "sleep ${FAKE_DIRENV_EXEC_SLEEP}" &
    wait
  fi
  exit "${FAKE_DIRENV_EXEC_EXIT:-0}"
fi
printf 'unexpected\t%s\n' "$*" >> "${FAKE_DIRENV_LOG}"
exit 99
`
	if err := os.WriteFile(scriptPath, []byte(fakeDirenvScript), 0o700); err != nil {
		t.Fatalf("write fake direnv: %v", err)
	}
	if statusExit == "" {
		statusExit = "0"
	}
	if execExit == "" {
		execExit = "0"
	}

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DIRENV_LOG", logPath)
	t.Setenv("FAKE_DIRENV_STATUS_JSON", statusJSON)
	t.Setenv("FAKE_DIRENV_STATUS_EXIT", statusExit)
	t.Setenv("FAKE_DIRENV_EXEC_EXIT", execExit)
	t.Setenv(vaultProxyIdentityEnv, "")
	if err := os.Unsetenv(vaultProxyIdentityEnv); err != nil {
		t.Fatalf("unset %s: %v", vaultProxyIdentityEnv, err)
	}
	return logPath
}

func readDirenvLinesByPrefix(t *testing.T, logPath, prefix string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("read fake direnv log: %v", err)
	}

	var matched []string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, prefix) {
			matched = append(matched, line)
		}
	}
	return matched
}

func assertErrState(t *testing.T, label string, err error, wantErr bool) {
	t.Helper()
	if (err != nil) != wantErr {
		t.Fatalf("%s error = %v, wantErr=%v", label, err, wantErr)
	}
}

func assertSingleStatusCall(t *testing.T, logPath, wantDir string) {
	t.Helper()
	lines := readDirenvLinesByPrefix(t, logPath, "status\t")
	if len(lines) != 1 {
		t.Fatalf("status calls = %d (%v), want 1", len(lines), lines)
	}
	want := "status\t" + wantDir + "\tstatus --json"
	if lines[0] != want {
		t.Errorf("status invocation = %q, want %q", lines[0], want)
	}
}

func assertNoExecCalls(t *testing.T, logPath string) {
	t.Helper()
	lines := readDirenvLinesByPrefix(t, logPath, "exec\t")
	if len(lines) != 0 {
		t.Fatalf("unexpected direnv exec invocations: %v", lines)
	}
}

func assertSingleExecCall(t *testing.T, logPath, wantDir, wantCmd, wantIdentity string) {
	t.Helper()
	lines := readDirenvLinesByPrefix(t, logPath, "exec\t")
	if len(lines) != 1 {
		t.Fatalf("exec calls = %d (%v), want 1", len(lines), lines)
	}
	parts := strings.Split(lines[0], "\t")
	wantParts := []string{"exec", wantDir, wantDir, "/bin/sh", "-c", wantCmd, wantIdentity}
	if len(parts) != len(wantParts) {
		t.Fatalf("exec fields = %q, want %q", parts, wantParts)
	}
	for i := range wantParts {
		if parts[i] != wantParts[i] {
			t.Errorf("exec field[%d] = %q, want %q", i, parts[i], wantParts[i])
		}
	}
}
