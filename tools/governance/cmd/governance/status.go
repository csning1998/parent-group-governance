package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cobra"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/converge"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/credentials"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/gitlabapi"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretrotate"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

const observeTimeout = 3 * time.Second

var (
	errNoObserveVaultAuth = errors.New("no authenticated Vault client available for observation")
	stageTitles           = []string{
		"Stage 0: Host Prerequisites",
		"Stage 1: Core Containers & Vault Init",
		"Stage 2: Bootstrap Facts & Manual Gate",
		"Stage 3: Trust Root Terraform",
		"Stage 4: Bastion Host Observability & Admin Password",
		"Stage 5: Downstream Terraform Layers & Credentials",
	}
	renderedLibvirtFiles = []string{
		filepath.Join("vault", "vault.hcl"),
		filepath.Join("vault", "vault.env"),
		filepath.Join("vault", "terminator", "haproxy.cfg"),
		filepath.Join("vault", "terminator", "terminator.env"),
	}
)

func (a *app) statusWriter() io.Writer {
	if a.stdout != nil {
		return a.stdout
	}
	return os.Stdout
}

func (a *app) errWriter() io.Writer {
	if a.stderr != nil {
		return a.stderr
	}
	return os.Stderr
}

func (a *app) newStatusCmd() *cobra.Command {
	var deep bool
	var target string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Inspect the Stage 0 to Stage 5 workstation convergence DAG",
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode := converge.ObserveFast
			if deep {
				mode = converge.ObserveDeep
			}
			return a.runStatus(cmd.Context(), mode, target)
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "Run Ansible --check and terraform plan on ready nodes")
	cmd.Flags().StringVar(&target, "to", "", "Limit status inspection to ancestors of a target node or stage")
	return cmd
}

func (a *app) runStatus(ctx context.Context, mode converge.ObserveMode, target string) error {
	graph, err := a.resolveWorkstationGraph()
	if err != nil {
		return err
	}
	bar, onProgress := a.startObserveProgress()
	reports, err := converge.ObserveWithProgress(ctx, graph, mode, target, onProgress)
	bar.Finish()
	if err != nil {
		return err
	}
	formatStatusTable(a.statusWriter(), reports)
	return nil
}

func (a *app) startObserveProgress() (*ui.ProgressBar, func(converge.ObserveEvent)) {
	errW := a.errWriter()
	bar := ui.NewProgressBar(errW, ui.IsTerminalWriter(errW))
	return bar, func(ev converge.ObserveEvent) {
		completed := max(ev.Index-1, 0)
		if ev.Done {
			completed = ev.Index
		}
		bar.Update(completed, ev.Total, ev.NodeID)
	}
}

func (a *app) resolveWorkstationGraph() (*converge.Graph, error) {
	if a.buildGraph != nil {
		return a.buildGraph()
	}
	return converge.BuildWorkstationGraph(a.buildWorkstationDeps())
}

func formatStatusTable(w io.Writer, reports []converge.NodeReport) {
	formatStatusTableWithColor(w, reports, ui.ShouldUseColor(w))
}

func formatStatusTableWithColor(w io.Writer, reports []converge.NodeReport, useColor bool) {
	lastStage := converge.Stage(-1)
	counts := make(map[converge.NodeState]int, 4)

	for _, rep := range reports {
		if rep.Stage != lastStage {
			_, _ = fmt.Fprintf(w, "\n%s\n", ui.Colorize(ui.Step, stageLabel(rep.Stage), useColor))
			lastStage = rep.Stage
		}
		counts[rep.State]++
		paddedState := fmt.Sprintf("%-10s", rep.State)
		coloredState := ui.Colorize(stateColorLevel(rep.State), paddedState, useColor)
		_, _ = fmt.Fprintf(w, "  %-42s  %s  %s\n", rep.ID, coloredState, rep.Summary)
		if rep.Hint != "" {
			_, _ = fmt.Fprintf(w, "    %s\n", ui.Colorize(ui.Warn, "hint: "+rep.Hint, useColor))
		}
	}
	_, _ = fmt.Fprintf(
		w,
		"\nSummary: %s, %s, %s, %s\n",
		formatSummaryCount(counts[converge.StateConverged], converge.StateConverged, useColor),
		formatSummaryCount(counts[converge.StateAbsent], converge.StateAbsent, useColor),
		formatSummaryCount(counts[converge.StateDrifted], converge.StateDrifted, useColor),
		formatSummaryCount(counts[converge.StateBlocked], converge.StateBlocked, useColor),
	)
}

func stateColorLevel(state converge.NodeState) ui.Level {
	switch state {
	case converge.StateConverged:
		return ui.OK
	case converge.StateAbsent:
		return ui.Task
	case converge.StateDrifted:
		return ui.Warn
	case converge.StateBlocked:
		return ui.Error
	default:
		return ui.Info
	}
}

func formatSummaryCount(count int, state converge.NodeState, useColor bool) string {
	text := fmt.Sprintf("%d %s", count, state)
	if !useColor {
		return text
	}
	if state != converge.StateConverged && count == 0 {
		return text
	}
	return ui.Colorize(stateColorLevel(state), text, true)
}

func stageLabel(stage converge.Stage) string {
	idx := int(stage)
	if idx >= 0 && idx < len(stageTitles) {
		return stageTitles[idx]
	}
	return fmt.Sprintf("Stage %d", idx)
}

func (a *app) buildWorkstationDeps() converge.WorkstationDeps {
	return converge.WorkstationDeps{
		Host: converge.HostObserverDeps{
			ProjectRoot:       a.root,
			Home:              a.home,
			InspectContainers: inspectPodmanContainers,
			InspectSELinux:    a.inspectHostSELinux,
			InspectLibvirt:    a.inspectHostLibvirt,
			InspectVaultProxy: a.inspectHostVaultProxy,
			InspectVaultAudit: a.inspectHostVaultAudit,
			InspectTelemetry:  a.inspectHostTelemetry,
			BootstrapEnv: func(context.Context, converge.ConvergeContext) error {
				env, err := config.BootstrapEnv(a.root, a.out)
				if err == nil {
					a.env = env
				}
				return err
			},
			ApplySELinux:    func(ctx context.Context, req converge.ConvergeContext) error { return a.runSELinuxStep(ctx, req) },
			EnsureTLSCA:     func(ctx context.Context, _ converge.ConvergeContext) error { return a.ensureLocalCA(ctx) },
			ApplyLibvirt:    func(ctx context.Context, req converge.ConvergeContext) error { return a.runLibvirtStep(ctx, req) },
			ApplyVaultProxy: func(ctx context.Context, req converge.ConvergeContext) error { return a.runVaultProxyStep(ctx, req) },
			StartContainers: a.startCoreContainers,
			ApplyVaultAudit: func(ctx context.Context, _ converge.ConvergeContext) error { return a.runHostVaultAuditPlaybook(ctx) },
			ApplyTelemetry:  func(ctx context.Context, req converge.ConvergeContext) error { return a.runTelemetrySteps(ctx, req) },
		},
		Vault: converge.VaultObserverDeps{
			ProjectRoot:     a.root,
			Home:            a.home,
			PublishIP:       a.topology.BastionVault.PublishIP,
			RootHygieneDeps: converge.DefaultRootHygieneDeps(),
			InspectSealStatus: func(ctx context.Context) vaultclient.SealStatus {
				return vaultclient.InspectStatus(ctx, a.newBastionVaultConfig())
			},
			VerifyFactoryDefault: a.verifyFactoryDefault,
			HasSecretMount:       a.hasSecretMount,
			ReadKVMap:            a.readVaultKVMap,
			WriteKVMap:           a.writeVaultKVMap,
			VerifyAdminProxy:     a.verifyAdminProxy,
			InitVault:            func(ctx context.Context, _ converge.ConvergeContext) error { return a.initVault(ctx) },
			UnsealVault:          func(ctx context.Context, _ converge.ConvergeContext) error { return a.unsealVault(ctx) },
			EnableKVSecret:       func(ctx context.Context, _ converge.ConvergeContext) error { return a.enableVaultKV(ctx) },
			RevokeRootToken:      a.convergeRevokeRootToken,
		},
		Terraform: converge.TerraformObserverDeps{
			ProjectRoot:          a.root,
			HasOperatorCertMount: a.hasOperatorCertMount,
			ReadKVMap:            a.readVaultKVMap,
			InspectLayerApplied:  a.inspectGitLabLayerApplied,
		},
		Credentials: converge.CredentialObserverDeps{
			ProjectRoot:                 a.root,
			RunnerConfigPath:            a.issuedTokens.GitLabGroupRunner.ConfigPath,
			ReadKVMap:                   a.readVaultKVMap,
			VerifySonarQubeAdmin:        a.verifySonarQubeAdmin,
			VerifyGroupVariable:         a.verifyGroupVariable,
			VerifyProjectVariables:      a.verifyProjectVariables,
			RotateSonarQubeAdmin:        a.convergeRotateSonarQubeAdmin,
			RegisterGitLabGroupRunner:   func(ctx context.Context, _ converge.ConvergeContext) error { return a.registerGitLabGroupRunner(ctx) },
			IssueSonarQubeAnalysisToken: func(ctx context.Context, _ converge.ConvergeContext) error { return a.issueSonarQubeAnalysisToken(ctx) },
			PublishCodeReviewerVariables: func(ctx context.Context, _ converge.ConvergeContext) error {
				return a.publishCodeReviewerVariables(ctx)
			},
		},
	}
}

func inspectPodmanContainers(ctx context.Context) ([]converge.ContainerState, error) {
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()

	out, err := exec.CommandContext(probeCtx, "podman", "ps", "-a", "--format", "json").Output()
	if err != nil {
		return nil, fmt.Errorf("status: podman ps: %w", err)
	}
	var entries []struct {
		Names  []string `json:"Names"`
		State  string   `json:"State"`
		Status string   `json:"Status"`
	}
	if err := json.Unmarshal(out, &entries); err != nil {
		return nil, fmt.Errorf("status: decode podman ps output: %w", err)
	}
	states := make([]converge.ContainerState, 0, len(entries))
	for _, entry := range entries {
		states = append(states, toContainerState(entry.Names, entry.State, entry.Status))
	}
	return states, nil
}

func toContainerState(names []string, rawState, rawStatus string) converge.ContainerState {
	name := ""
	if len(names) > 0 {
		name = names[0]
	}
	running := strings.EqualFold(rawState, "running")
	lowerStatus := strings.ToLower(rawStatus)
	healthy := running && !strings.Contains(lowerStatus, "unhealthy") && !strings.Contains(lowerStatus, "starting")
	return converge.ContainerState{Name: name, Running: running, Healthy: healthy}
}

func (a *app) inspectHostSELinux(ctx context.Context, _ converge.ObserveMode) (converge.NodeState, string, error) {
	target := filepath.Join(a.root, "vault", "data")
	if _, err := os.Stat(target); errors.Is(err, fs.ErrNotExist) {
		target = filepath.Join(a.root, "vault")
	}
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()

	out, err := exec.CommandContext(probeCtx, "ls", "-Zd", target).Output()
	if err != nil {
		return converge.StateAbsent, "target directory not labeled yet", nil
	}
	if strings.Contains(string(out), "container_file_t") {
		return converge.StateConverged, "SELinux container_file_t context present", nil
	}
	return converge.StateDrifted, "target lacks container_file_t label", nil
}

func (a *app) inspectHostLibvirt(_ context.Context, _ converge.ObserveMode) (converge.NodeState, string, error) {
	present := 0
	for _, rel := range renderedLibvirtFiles {
		if _, err := os.Stat(filepath.Join(a.root, rel)); err == nil {
			present++
		}
	}
	switch present {
	case 0:
		return converge.StateAbsent, "rendered vault/haproxy configs absent", nil
	case len(renderedLibvirtFiles):
		return converge.StateConverged, "all 4 libvirt/Vault rendered configs present", nil
	default:
		return converge.StateDrifted, fmt.Sprintf("%d/%d rendered configs present", present, len(renderedLibvirtFiles)), nil
	}
}

func (a *app) inspectHostVaultProxy(ctx context.Context, _ converge.ObserveMode) (converge.NodeState, string, error) {
	base := filepath.Join(a.home, a.topology.OperatorVaultProxy.UserConfigDir)
	if _, err := os.Stat(filepath.Join(base, "ca.pem")); errors.Is(err, fs.ErrNotExist) {
		return converge.StateAbsent, "Vault Proxy mTLS config absent", nil
	}
	missing := 0
	for identity := range a.topology.OperatorVaultProxy.Identities {
		if _, err := os.Stat(filepath.Join(base, identity, "client.pem")); err != nil {
			missing++
		}
	}
	if missing > 0 {
		return converge.StateDrifted, fmt.Sprintf("%d Vault Proxy identity certs missing", missing), nil
	}
	if !isUserUnitActive(ctx, "vault-proxy@administrator.service") {
		return converge.StateDrifted, "vault-proxy@administrator.service inactive", nil
	}
	return converge.StateConverged, "Vault Proxy mTLS certs and service active", nil
}

func (a *app) inspectHostVaultAudit(ctx context.Context, _ converge.ObserveMode) (converge.NodeState, string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()

	out, err := exec.CommandContext(probeCtx, "systemctl", "--user", "is-enabled", "vault-audit-check.timer").Output()
	if err != nil {
		return converge.StateAbsent, "vault-audit-check.timer not installed", nil
	}
	if strings.TrimSpace(string(out)) == "enabled" {
		return converge.StateConverged, "vault-audit-check.timer enabled", nil
	}
	return converge.StateDrifted, "vault-audit-check.timer disabled", nil
}

func (a *app) inspectHostTelemetry(_ context.Context, _ converge.ObserveMode) (converge.NodeState, string, error) {
	_, factErr := os.Stat("/etc/ansible/facts.d/host_telemetry.fact")
	_, cfgErr := os.Stat(filepath.Join(a.root, "vault", "terminator", "haproxy-telemetry.cfg"))
	switch {
	case factErr != nil && cfgErr != nil:
		return converge.StateAbsent, "host telemetry fact and haproxy config absent", nil
	case factErr == nil && cfgErr == nil:
		return converge.StateConverged, "host telemetry fact and haproxy config present", nil
	default:
		return converge.StateDrifted, "host telemetry artifacts partially present", nil
	}
}

func isUserUnitActive(ctx context.Context, unit string) bool {
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()
	return exec.CommandContext(probeCtx, "systemctl", "--user", "is-active", "--quiet", unit).Run() == nil
}

func (a *app) newObserveVaultClient(ctx context.Context) (*vaultapi.Client, error) {
	if cfg, err := a.buildProxyConfig(accessAdministrator); err == nil {
		if client, err := newBoundedVaultClient(cfg); err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
			_, lookupErr := client.Auth().Token().LookupSelfWithContext(probeCtx)
			cancel()
			if lookupErr == nil {
				return client, nil
			}
		}
	}
	token := vaultclient.ReadTokenFile(a.home)
	if token == "" {
		return nil, errNoObserveVaultAuth
	}
	cfg := a.newBastionVaultConfig()
	cfg.Token = token
	return newBoundedVaultClient(cfg)
}

func newBoundedVaultClient(cfg vaultclient.Config) (*vaultapi.Client, error) {
	client, err := vaultclient.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	client.SetMaxRetries(0)
	client.SetClientTimeout(observeTimeout)
	return client, nil
}

func (a *app) hasSecretMount(ctx context.Context) (bool, error) {
	client, err := a.newObserveVaultClient(ctx)
	if err != nil {
		if errors.Is(err, errNoObserveVaultAuth) {
			return false, nil
		}
		return false, err
	}
	mounts, err := client.Sys().ListMountsWithContext(ctx)
	if err != nil {
		return false, nil
	}
	_, exists := mounts["secret/"]
	return exists, nil
}

func (a *app) hasOperatorCertMount(ctx context.Context) (bool, error) {
	client, err := a.newObserveVaultClient(ctx)
	if err != nil {
		if errors.Is(err, errNoObserveVaultAuth) {
			return false, nil
		}
		return false, nil
	}
	auths, err := client.Sys().ListAuthWithContext(ctx)
	if err != nil {
		return false, nil
	}
	mountName := strings.TrimSuffix(a.topology.OperatorVaultProxy.CertAuthMount, "/") + "/"
	_, exists := auths[mountName]
	return exists, nil
}

func (a *app) readVaultKVMap(ctx context.Context, mount, path string) (map[string]string, bool, error) {
	client, err := a.newObserveVaultClient(ctx)
	if err != nil {
		if errors.Is(err, errNoObserveVaultAuth) {
			return nil, false, nil
		}
		return nil, false, err
	}
	secret, err := client.KVv2(mount).Get(ctx, path)
	if err != nil {
		if errors.Is(err, vaultapi.ErrSecretNotFound) || strings.Contains(strings.ToLower(err.Error()), "secret not found") {
			return nil, false, nil
		}
		return nil, false, nil
	}
	if secret == nil || secret.Data == nil {
		return nil, false, nil
	}
	out := make(map[string]string, len(secret.Data))
	for k, v := range secret.Data {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out, true, nil
}

func (a *app) writeVaultKVMap(ctx context.Context, mount, path string, data map[string]string) error {
	client, err := a.newObserveVaultClient(ctx)
	if err != nil {
		return err
	}
	payload := make(map[string]any, len(data))
	for k, v := range data {
		payload[k] = v
	}
	_, err = client.KVv2(mount).Put(ctx, path, payload)
	return err
}

func (a *app) verifyAdminProxy(ctx context.Context) (bool, error) {
	cfg, err := a.buildProxyConfig(accessAdministrator)
	if err != nil {
		return false, nil
	}
	client, err := newBoundedVaultClient(cfg)
	if err != nil {
		return false, nil
	}
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()
	_, err = client.Auth().Token().LookupSelfWithContext(probeCtx)
	return err == nil, nil
}

func (a *app) verifyFactoryDefault(ctx context.Context) (bool, string, error) {
	probeCtx, cancel := context.WithTimeout(ctx, observeTimeout)
	defer cancel()
	for _, cred := range a.credentials {
		if cred.Spec.FactoryDefaultPassword == "" || cred.Spec.Verify == nil {
			continue
		}
		fresh, err := secretrotate.AwaitFactoryDefault(probeCtx, cred.Spec, 500*time.Millisecond)
		if err != nil {
			return true, "", nil
		}
		if !fresh {
			return false, cred.Key, nil
		}
	}
	return true, "", nil
}

func (a *app) newObserveGitLabClient(ctx context.Context) (client *gitlabapi.Client, topLevelGroup, groupID string, ok bool) {
	origin, err := a.resolveOrigin(ctx)
	if err != nil {
		return nil, "", "", false
	}
	location, err := a.topology.ResolveStateBackendToken(a.topology.OperatorVaultProxy.GovernanceOwnerCode)
	if err != nil {
		return nil, "", "", false
	}
	stateKV, found, err := a.readVaultKVMap(ctx, location.Mount, location.Path)
	if err != nil || !found || stateKV[location.Field] == "" {
		return nil, "", "", false
	}
	regRef := a.issuedTokens.GitLabGroupRegistry
	regKV, found, err := a.readVaultKVMap(ctx, regRef.Mount, regRef.Path)
	if err != nil || !found || regKV[regRef.Field] == "" {
		return nil, "", "", false
	}
	return gitlabapi.New(origin.APIURL, stateKV[location.Field]), origin.TopLevelGroup, regKV[regRef.Field], true
}

func (a *app) inspectGitLabLayerApplied(ctx context.Context, layerDir string) (bool, error) {
	client, topLevelGroup, groupID, ok := a.newObserveGitLabClient(ctx)
	if !ok {
		return false, nil
	}
	switch filepath.Base(layerDir) {
	case "administration-gitlab-project":
		return client.HasProject(ctx, topLevelGroup+"/parent-group-governance")
	case "group-gitlab-configuration":
		return client.HasGroupVariable(ctx, groupID, "SONAR_HOST_URL")
	default:
		return false, nil
	}
}

func (a *app) verifySonarQubeAdmin(ctx context.Context) (bool, error) {
	cfg := a.issuedTokens.SonarQubeAnalysisToken
	cred, ok := credentials.Lookup(a.credentials, cfg.AdminPasswordKey)
	if !ok || cred.Spec.Verify == nil {
		return true, nil
	}
	kv, found, err := a.readVaultKVMap(ctx, cred.Spec.Mount, cred.Spec.Path)
	if err != nil || !found {
		return false, err
	}
	pw := kv[cred.Spec.Field]
	if pw == "" {
		return false, nil
	}
	return cred.Spec.Verify(ctx, pw)
}

func (a *app) verifyGroupVariable(ctx context.Context, key string) (bool, error) {
	client, _, groupID, ok := a.newObserveGitLabClient(ctx)
	if !ok {
		return false, nil
	}
	return client.HasGroupVariable(ctx, groupID, key)
}

func (a *app) verifyProjectVariables(ctx context.Context) (present, total int, err error) {
	client, topLevelGroup, _, ok := a.newObserveGitLabClient(ctx)
	if !ok {
		return 0, countExpectedProjectVars(a), nil
	}
	projects := a.topology.ListCodeReviewerVariableProjects(topLevelGroup)
	for _, projectPath := range projects {
		for _, bot := range a.issuedTokens.CodeReviewerVariables.BotTokens {
			for _, key := range bot.VariableKeys {
				total++
				hasVar, varErr := client.HasProjectVariable(ctx, projectPath, key)
				if varErr == nil && hasVar {
					present++
				}
			}
		}
	}
	return present, total, nil
}

func countExpectedProjectVars(a *app) int {
	origin, err := a.resolveOrigin(context.Background())
	if err != nil {
		return 0
	}
	projects := a.topology.ListCodeReviewerVariableProjects(origin.TopLevelGroup)
	keysPerProject := 0
	for _, bot := range a.issuedTokens.CodeReviewerVariables.BotTokens {
		keysPerProject += len(bot.VariableKeys)
	}
	return len(projects) * keysPerProject
}
