package terraform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

// PlanOutcome classifies the result of terraform plan -detailed-exitcode.
type PlanOutcome string

const (
	// PlanConverged indicates terraform plan exited with 0 (no pending changes).
	PlanConverged PlanOutcome = "converged"
	// PlanDrifted indicates terraform plan exited with 2 (pending changes detected).
	PlanDrifted PlanOutcome = "drifted"

	direnvBinary                          = "direnv"
	vaultProxyIdentityEnv                 = "VAULT_PROXY_IDENTITY"
	terraformPlanShellCommand             = "terraform init -input=false >/dev/null && terraform plan -detailed-exitcode -input=false"
	terraformApplyShellCommand            = "terraform init -input=false && terraform apply"
	terraformApplyAutoApproveShellCommand = "terraform init -input=false && terraform apply -auto-approve"
)

// RunRequest configures a direnv-scoped Terraform plan or apply execution.
type RunRequest struct {
	LayerDir              string
	BootstrapRootIdentity bool
	AutoApprove           bool
	Stdin                 io.Reader
	Stdout                io.Writer
	Stderr                io.Writer
}

// PlanLayer initializes and plans req.LayerDir via direnv exec using -detailed-exitcode.
func PlanLayer(ctx context.Context, req RunRequest) (PlanOutcome, error) {
	if err := requireDirenvAllowed(ctx, req.LayerDir); err != nil {
		return "", err
	}

	exitCode, err := runDirenvShell(ctx, req, terraformPlanShellCommand)
	switch exitCode {
	case 0:
		return PlanConverged, nil
	case 2:
		return PlanDrifted, nil
	default:
		return "", fmt.Errorf("terraform: plan %s failed: %w", req.LayerDir, err)
	}
}

// ApplyLayer initializes and applies req.LayerDir via direnv exec.
func ApplyLayer(ctx context.Context, req RunRequest) error {
	if err := requireDirenvAllowed(ctx, req.LayerDir); err != nil {
		return err
	}

	applyCommand := terraformApplyShellCommand
	if req.AutoApprove {
		applyCommand = terraformApplyAutoApproveShellCommand
	}
	if _, err := runDirenvShell(ctx, req, applyCommand); err != nil {
		return fmt.Errorf("terraform: apply %s failed: %w", req.LayerDir, err)
	}
	return nil
}

func requireDirenvAllowed(ctx context.Context, dir string) error {
	allowed, rcPath, err := VerifyDirenvAllowed(ctx, dir)
	if err != nil {
		return err
	}
	if allowed {
		return nil
	}
	target := dir
	if rcPath != "" {
		target = rcPath
	}
	return fmt.Errorf("%w: %s (run direnv allow)", ErrDirenvNotAllowed, target)
}

func buildSubprocessEnv(bootstrapRootIdentity bool) []string {
	environ := os.Environ()
	env := make([]string, 0, len(environ)+1)
	prefix := vaultProxyIdentityEnv + "="
	for _, entry := range environ {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		env = append(env, entry)
	}
	if bootstrapRootIdentity {
		env = append(env, prefix+"root")
	}
	return env
}

func runDirenvShell(ctx context.Context, req RunRequest, shellCommand string) (int, error) {
	cmd := exec.CommandContext(ctx, direnvBinary, "exec", req.LayerDir, "/bin/sh", "-c", shellCommand)
	cmd.Dir = req.LayerDir
	cmd.Stdin = req.Stdin
	cmd.Stdout = req.Stdout
	var capturedStderr bytes.Buffer
	if req.Stderr != nil {
		cmd.Stderr = req.Stderr
	} else {
		cmd.Stderr = &capturedStderr
	}
	cmd.Env = buildSubprocessEnv(req.BootstrapRootIdentity)
	isInteractiveApply := req.Stdin != nil && !req.AutoApprove && shellCommand == terraformApplyShellCommand
	useProcessGroup := !isInteractiveApply
	if useProcessGroup {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
	}

	if err := cmd.Start(); err != nil {
		return -1, err
	}

	var wg sync.WaitGroup
	sigCh := make(chan os.Signal, 2)
	done := make(chan struct{})
	if useProcessGroup {
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		wg.Add(1)
		go func() {
			defer wg.Done()
			forwardSignalsToGroup(cmd.Process.Pid, sigCh, done)
		}()
	}

	err := cmd.Wait()
	if useProcessGroup {
		signal.Stop(sigCh)
		close(done)
		wg.Wait()
	}

	if err == nil {
		return 0, nil
	}
	exitCode := -1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	if msg := strings.TrimSpace(capturedStderr.String()); msg != "" {
		return exitCode, fmt.Errorf("%w: %s", err, msg)
	}
	return exitCode, err
}

func forwardSignalsToGroup(pid int, sigCh <-chan os.Signal, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case sig := <-sigCh:
			if sysSig, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-pid, sysSig)
			}
		}
	}
}
