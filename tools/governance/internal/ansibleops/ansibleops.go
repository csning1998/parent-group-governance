// Package ansibleops executes ansible-playbook tasks via go-ansible under ANSIBLE_CONFIG scoping.
package ansibleops

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
)

// RunPlaybook executes playbookFile using opts while injecting ANSIBLE_CONFIG derived from ansibleDir.
// If runDir is non-empty, sets the command execution directory to runDir to resolve relative playbook paths.
// extraEnv is merged into the child process environment. A nil map is valid.
func RunPlaybook(ctx context.Context, ansibleDir, runDir, playbookFile string, opts *playbook.AnsiblePlaybookOptions, extraEnv map[string]string) error {
	cmd := playbook.NewAnsiblePlaybookCmd(
		playbook.WithPlaybooks(playbookFile),
		playbook.WithPlaybookOptions(opts),
	)

	env := map[string]string{
		"ANSIBLE_CONFIG":      filepath.Join(ansibleDir, "ansible.cfg"),
		"ANSIBLE_FORCE_COLOR": "1",
	}
	for k, v := range extraEnv {
		env[k] = v
	}

	execOpts := []execute.ExecuteOptions{
		execute.WithCmd(cmd),
		execute.WithEnvVars(env),
	}
	if runDir != "" {
		execOpts = append(execOpts, execute.WithCmdRunDir(runDir))
	}

	// The go-ansible error lists every variable of extraEnv, including the become password, and wraps no cause.
	// The playbook output already shows the failing task on the terminal.
	if err := execute.NewDefaultExecute(execOpts...).Execute(ctx); err != nil {
		return fmt.Errorf("%s failed, the task output above names the failing task", playbookFile)
	}
	return nil
}
