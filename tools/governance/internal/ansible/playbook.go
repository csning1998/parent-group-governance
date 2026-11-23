// Package ansible executes ansible-playbook tasks via go-ansible with explicit ANSIBLE_CONFIG scoping.
package ansible

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

// PlaybookRequest contains the paths, options, and environment overrides for an ansible-playbook run.
type PlaybookRequest struct {
	AnsibleDir   string
	RunDir       string
	PlaybookFile string
	Options      *playbook.AnsiblePlaybookOptions
	ExtraEnv     map[string]string
}

// ExecutePlaybook executes req.PlaybookFile with ANSIBLE_CONFIG pointing to req.AnsibleDir/ansible.cfg.
// When req.RunDir is specified, ExecutePlaybook executes from req.RunDir to resolve relative playbook paths.
// A nil req.ExtraEnv map is valid.
func ExecutePlaybook(ctx context.Context, req PlaybookRequest) error {
	cmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(req.PlaybookFile),
		playbook.WithPlaybookOptions(req.Options),
	)

	env := map[string]string{
		"ANSIBLE_CONFIG":      filepath.Join(req.AnsibleDir, "ansible.cfg"),
		"ANSIBLE_FORCE_COLOR": "1",
	}
	maps.Copy(env, req.ExtraEnv)

	execOpts := []execute.ExecuteOptions{
		execute.WithCmd(cmd),
		execute.WithEnvVars(env),
	}
	if req.RunDir != "" {
		execOpts = append(execOpts, execute.WithCmdRunDir(req.RunDir))
	}

	// The go-ansible error lists every variable of extraEnv, including the become password.
	// Omit err because the go-ansible error does not wrap a cause and terminal output already shows the failing task.
	if err := execute.NewDefaultExecute(execOpts...).Execute(ctx); err != nil {
		return fmt.Errorf("%s failed, the task output above names the failing task", req.PlaybookFile)
	}
	return nil
}
