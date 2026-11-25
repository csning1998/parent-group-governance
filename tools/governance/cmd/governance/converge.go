package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
)

type convergeFlags struct {
	target      string
	dryRun      bool
	autoApprove bool
	deep        bool
}

func (a *app) newConvergeCmd() *cobra.Command {
	var flags convergeFlags
	cmd := &cobra.Command{
		Use:   "converge",
		Short: "Converge absent and drifted nodes along the workstation DAG",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return a.runConverge(cmd.Context(), flags)
		},
	}
	cmd.Flags().StringVar(&flags.target, "to", "", "Stop convergence at the named stage or node ID")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Print planned convergence actions without modifying state")
	cmd.Flags().BoolVar(&flags.autoApprove, "auto-approve", false, "Pass -auto-approve to Terraform apply invocations")
	cmd.Flags().BoolVar(&flags.deep, "deep", false, "Observe using Ansible --check and terraform plan before converging")
	return cmd
}

func (a *app) runConverge(ctx context.Context, flags convergeFlags) error {
	graph, err := a.resolveWorkstationGraph()
	if err != nil {
		return err
	}
	mode := converge.ObserveFast
	if flags.deep {
		mode = converge.ObserveDeep
	}

	plan, err := converge.Converge(ctx, graph, converge.ConvergeOptions{
		Target: flags.target,
		Mode:   mode,
		DryRun: true,
	})
	if err != nil {
		return err
	}
	formatStatusTable(a.statusWriter(), plan.Reports)

	if flags.dryRun {
		a.printDryRunPlan(plan.Planned)
		return nil
	}
	if len(plan.Planned) == 0 {
		return handleNoPlannedNodes(a.statusWriter(), plan.Blocked)
	}

	_, _ = fmt.Fprintf(a.statusWriter(), "\nPlanned nodes (%d): %s\n", len(plan.Planned), strings.Join(plan.Planned, ", "))
	if !a.out.PromptConfirm(a.in, "Proceed with convergence? Type 'Y' or 'y' to confirm: ") {
		a.out.Print(ui.Info, msgCancelled)
		return nil
	}

	promptFn := a.promptBecome
	if promptFn == nil {
		promptFn = a.promptBecomePassword
	}
	res, err := converge.Converge(ctx, graph, converge.ConvergeOptions{
		Target:       flags.target,
		Mode:         mode,
		AutoApprove:  flags.autoApprove,
		PromptBecome: promptFn,
		Stdout:       a.statusWriter(),
		Stderr:       a.errWriter(),
	})
	if err != nil {
		return err
	}
	if len(res.Blocked) > 0 {
		return fmt.Errorf("converge completed %d nodes; blocked on %s", len(res.Executed), strings.Join(res.Blocked, ", "))
	}
	a.out.Print(ui.OK, fmt.Sprintf("Converged %d nodes.", len(res.Executed)))
	return nil
}

func (a *app) printDryRunPlan(planned []string) {
	if len(planned) == 0 {
		_, _ = fmt.Fprintln(a.statusWriter(), "\nDry-run: no nodes require convergence.")
		return
	}
	_, _ = fmt.Fprintf(a.statusWriter(), "\nDry-run planned nodes (%d): %s\n", len(planned), strings.Join(planned, ", "))
}

func handleNoPlannedNodes(w interface{ Write([]byte) (int, error) }, blocked []string) error {
	if len(blocked) > 0 {
		return fmt.Errorf("converge blocked on %d nodes: %s", len(blocked), strings.Join(blocked, ", "))
	}
	_, _ = fmt.Fprintln(w, "\nAll targeted nodes are converged.")
	return nil
}

func (a *app) promptBecomePassword(_ context.Context) (converge.BecomePassword, error) {
	pw, err := a.out.PromptSecret(a.in, int(os.Stdin.Fd()), "ANSIBLE_BECOME_PASS: ")
	if err != nil {
		return "", fmt.Errorf("read ANSIBLE_BECOME_PASS: %w", err)
	}
	if pw == "" {
		return "", fmt.Errorf("converge: empty ANSIBLE_BECOME_PASS cancelled execution")
	}
	return converge.BecomePassword(pw), nil
}

func (a *app) runSELinuxStep(ctx context.Context, req converge.ConvergeContext) error {
	return a.playbookStep(a.buildSELinuxPlaybook)(ctx, req.BecomePassword.Value())
}

func (a *app) runLibvirtStep(ctx context.Context, req converge.ConvergeContext) error {
	return a.playbookStep(a.buildLibvirtPlaybook)(ctx, req.BecomePassword.Value())
}

func (a *app) runVaultProxyStep(ctx context.Context, req converge.ConvergeContext) error {
	return a.playbookStep(func() (hostPlaybook, error) { return a.buildVaultProxyPlaybook(ctx) })(ctx, req.BecomePassword.Value())
}

func (a *app) runTelemetrySteps(ctx context.Context, req converge.ConvergeContext) error {
	becomePass := req.BecomePassword.Value()
	if err := a.playbookStep(func() (hostPlaybook, error) { return a.buildHostTelemetryPlaybook(ctx) })(ctx, becomePass); err != nil {
		return err
	}
	return a.playbookStep(a.buildLibvirtPlaybook)(ctx, becomePass)
}

func (a *app) startCoreContainers(ctx context.Context, _ converge.ConvergeContext) error {
	cmd := exec.CommandContext(ctx, "podman", "compose", "up", "-d")
	cmd.Dir = a.root
	cmd.Stdout = a.statusWriter()
	cmd.Stderr = a.errWriter()
	return cmd.Run()
}

func (a *app) convergeRevokeRootToken(ctx context.Context, _ converge.ConvergeContext) error {
	ep, err := a.topology.ResolveProxyEndpoint(a.home, accessAdministrator)
	if err != nil {
		return err
	}
	op, err := a.newVaultOperator()
	if err != nil {
		return err
	}
	return op.RevokeRoot(ctx, newProxyConfig(ep), "operator-"+ep.Identity)
}

func (a *app) convergeRotateSonarQubeAdmin(ctx context.Context, _ converge.ConvergeContext) error {
	key := a.issuedTokens.SonarQubeAnalysisToken.AdminPasswordKey
	if key == "" && len(a.credentials) > 0 {
		key = a.credentials[0].Key
	}
	cred, ok := credentials.Lookup(a.credentials, key)
	if !ok {
		return fmt.Errorf("converge: no registered credential %q", key)
	}
	client, err := a.newRotationClient()
	if err != nil {
		return err
	}
	_, err = secretrotate.Rotate(ctx, client, cred.Spec, func(msg string) { a.out.Print(ui.OK, msg) })
	return err
}
