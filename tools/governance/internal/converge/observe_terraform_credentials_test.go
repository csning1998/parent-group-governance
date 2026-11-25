package converge

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/terraform"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestTerraformFoundationBastionNode(t *testing.T) {
	root := t.TempDir()
	wantDir := filepath.Join(root, "terraform", "layers", "foundation-vault-bastion")

	t.Run("unallowed direnv blocks with direnv allow hint", func(t *testing.T) {
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot: root,
			VerifyDirenvAllowed: func(context.Context, string) (bool, string, error) {
				return false, filepath.Join(wantDir, ".envrc"), nil
			},
		}), NodeTerraformFoundationVaultBastion)
		rep := assertInspectState(t, node, ObserveFast, StateBlocked)
		assertHintContains(t, rep, "direnv allow")
	})

	t.Run("absent operator-cert mount reports absent and bootstraps root identity", func(t *testing.T) {
		var gotReq terraform.RunRequest
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot:          root,
			VerifyDirenvAllowed:  allowAllDirenv,
			HasOperatorCertMount: func(context.Context) (bool, error) { return false, nil },
			ApplyLayer: func(_ context.Context, req terraform.RunRequest) error {
				gotReq = req
				return nil
			},
		}), NodeTerraformFoundationVaultBastion)
		assertInspectState(t, node, ObserveFast, StateAbsent)
		if err := node.Converge(context.Background(), ConvergeContext{AutoApprove: false}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if gotReq.LayerDir != wantDir || !gotReq.BootstrapRootIdentity {
			t.Errorf("ApplyLayer req = (%q, bootstrap=%v), want (%q, bootstrap=true)", gotReq.LayerDir, gotReq.BootstrapRootIdentity, wantDir)
		}
	})

	t.Run("present operator-cert mount reports converged fast and drifted deep", func(t *testing.T) {
		var gotReq terraform.RunRequest
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot:          root,
			VerifyDirenvAllowed:  allowAllDirenv,
			HasOperatorCertMount: func(context.Context) (bool, error) { return true, nil },
			PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
				return terraform.PlanDrifted, nil
			},
			ApplyLayer: func(_ context.Context, req terraform.RunRequest) error {
				gotReq = req
				return nil
			},
		}), NodeTerraformFoundationVaultBastion)
		assertInspectState(t, node, ObserveFast, StateConverged)
		assertInspectState(t, node, ObserveDeep, StateDrifted)
		if err := node.Converge(context.Background(), ConvergeContext{AutoApprove: true}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if gotReq.BootstrapRootIdentity || !gotReq.AutoApprove {
			t.Errorf("ApplyLayer req = (bootstrap=%v, autoApprove=%v), want (false, true)", gotReq.BootstrapRootIdentity, gotReq.AutoApprove)
		}
	})
}

func TestTerraformAnthropicOAuthGate(t *testing.T) {
	nodeIDs := []string{
		NodeTerraformGroupAIProviderAnthropic,
		NodeTerraformAdministrationGitLab,
	}
	for _, nodeID := range nodeIDs {
		t.Run(nodeID, func(t *testing.T) {
			runAnthropicOAuthGateSuite(t, nodeID)
		})
	}
}

func runAnthropicOAuthGateSuite(t *testing.T, nodeID string) {
	t.Helper()
	root := t.TempDir()

	t.Run("fast applied reports converged without oauth token", func(t *testing.T) {
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot:         root,
			VerifyDirenvAllowed: allowAllDirenv,
			InspectLayerApplied: func(context.Context, string) (bool, error) { return true, nil },
			ReadKVMap: func(_ context.Context, mount, path string) (map[string]string, bool, error) {
				if mount == "registry" && path == "platform/ai-provider/anthropic" {
					return map[string]string{"issuer_id": "example-issuer"}, true, nil
				}
				return nil, false, nil
			},
		}), nodeID)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})

	t.Run("fast unapplied without oauth token blocks with ant auth hint", func(t *testing.T) {
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot:         root,
			VerifyDirenvAllowed: allowAllDirenv,
			InspectLayerApplied: func(context.Context, string) (bool, error) { return false, nil },
			ReadKVMap:           func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
		}), nodeID)
		rep := assertInspectState(t, node, ObserveFast, StateBlocked)
		assertHintContains(t, rep, "ant auth", "anthropic_oauth_access_token")
	})

	t.Run("deep without oauth token blocks before plan", func(t *testing.T) {
		planned := 0
		node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
			ProjectRoot:         root,
			VerifyDirenvAllowed: allowAllDirenv,
			InspectLayerApplied: func(context.Context, string) (bool, error) { return true, nil },
			ReadKVMap: func(_ context.Context, mount, path string) (map[string]string, bool, error) {
				if mount == "registry" {
					return map[string]string{"issuer_id": "example-issuer"}, true, nil
				}
				return map[string]string{"anthropic_admin_api_key": "example-key"}, true, nil
			},
			PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
				planned++
				return terraform.PlanConverged, nil
			},
		}), nodeID)
		assertInspectState(t, node, ObserveDeep, StateBlocked)
		if planned != 0 {
			t.Errorf("PlanLayer calls = %d, want 0", planned)
		}
	})

	t.Run("deep with oauth token delegates to plan", func(t *testing.T) {
		assertDeepPlanMapsOutcome(t, root, nodeID, terraform.PlanConverged, StateConverged)
		assertDeepPlanMapsOutcome(t, root, nodeID, terraform.PlanDrifted, StateDrifted)
	})
}

func assertDeepPlanMapsOutcome(t *testing.T, root, nodeID string, outcome terraform.PlanOutcome, want NodeState) {
	t.Helper()
	node := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: allowAllDirenv,
		InspectLayerApplied: func(context.Context, string) (bool, error) { return true, nil },
		ReadKVMap: func(_ context.Context, mount, path string) (map[string]string, bool, error) {
			if mount == "registry" {
				return map[string]string{"issuer_id": "example-issuer"}, true, nil
			}
			return map[string]string{"anthropic_oauth_access_token": "example-oauth"}, true, nil
		},
		PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
			return outcome, nil
		},
	}), nodeID)
	assertInspectState(t, node, ObserveDeep, want)
}

func TestTerraformDownstreamLayersFastAndDeep(t *testing.T) {
	registryLayers := []struct {
		id           string
		registryPath string
	}{
		{id: NodeTerraformGroupFoundation, registryPath: "platform/gitlab-group/top-level"},
		{id: NodeTerraformGroupAIProviderGoogle, registryPath: "platform/ai-provider/google-cloud"},
		{id: NodeTerraformGroupAIProviderAzure, registryPath: "platform/ai-provider/azure"},
		{id: NodeTerraformGroupTopology, registryPath: "platform/gitlab-group/subgroups"},
	}
	for _, tc := range registryLayers {
		t.Run(tc.id, func(t *testing.T) {
			assertRegistryLayerFastAndDeep(t, tc.id, tc.registryPath)
		})
	}

	t.Run(NodeTerraformGroupGitLabConfiguration, func(t *testing.T) {
		assertInspectLayerAppliedFastAndDeep(t, NodeTerraformGroupGitLabConfiguration)
	})
}

func assertRegistryLayerFastAndDeep(t *testing.T, nodeID, registryPath string) {
	t.Helper()
	root := t.TempDir()

	blocked := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: func(context.Context, string) (bool, string, error) { return false, "", nil },
	}), nodeID)
	assertInspectState(t, blocked, ObserveFast, StateBlocked)

	absent := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: allowAllDirenv,
		ReadKVMap:           func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
		PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
			return terraform.PlanDrifted, nil
		},
	}), nodeID)
	assertInspectState(t, absent, ObserveFast, StateAbsent)
	assertInspectState(t, absent, ObserveDeep, StateAbsent)

	converged := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: allowAllDirenv,
		ReadKVMap: func(_ context.Context, mount, path string) (map[string]string, bool, error) {
			if mount == "registry" && path == registryPath {
				return map[string]string{"id": "example"}, true, nil
			}
			return nil, false, nil
		},
		PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
			return terraform.PlanConverged, nil
		},
	}), nodeID)
	assertInspectState(t, converged, ObserveFast, StateConverged)
	assertInspectState(t, converged, ObserveDeep, StateConverged)
}

func assertInspectLayerAppliedFastAndDeep(t *testing.T, nodeID string) {
	t.Helper()
	root := t.TempDir()

	blocked := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: func(context.Context, string) (bool, string, error) { return false, "", nil },
	}), nodeID)
	assertInspectState(t, blocked, ObserveFast, StateBlocked)

	drifted := findNodeByID(t, BuildTerraformNodes(TerraformObserverDeps{
		ProjectRoot:         root,
		VerifyDirenvAllowed: allowAllDirenv,
		InspectLayerApplied: func(context.Context, string) (bool, error) { return true, nil },
		PlanLayer: func(context.Context, terraform.RunRequest) (terraform.PlanOutcome, error) {
			return terraform.PlanDrifted, nil
		},
	}), nodeID)
	assertInspectState(t, drifted, ObserveFast, StateConverged)
	assertInspectState(t, drifted, ObserveDeep, StateDrifted)
}

func TestCredentialSonarQubeAdminPasswordNode(t *testing.T) {
	t.Run("missing vault field reports absent", func(t *testing.T) {
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap: func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
		}), NodeCredentialsSonarQubeAdminPassword)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("vault present and live check passes reports converged", func(t *testing.T) {
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap:            readSonarAdminKV,
			VerifySonarQubeAdmin: func(context.Context) (bool, error) { return true, nil },
		}), NodeCredentialsSonarQubeAdminPassword)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})

	t.Run("vault present and live check fails reports drifted and converges", func(t *testing.T) {
		rotated := 0
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap:            readSonarAdminKV,
			VerifySonarQubeAdmin: func(context.Context) (bool, error) { return false, nil },
			RotateSonarQubeAdmin: func(context.Context, ConvergeContext) error {
				rotated++
				return nil
			},
		}), NodeCredentialsSonarQubeAdminPassword)
		assertInspectState(t, node, ObserveFast, StateDrifted)
		if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if rotated != 1 {
			t.Errorf("RotateSonarQubeAdmin calls = %d, want 1", rotated)
		}
	})
}

func TestCredentialGitLabGroupRunnerNode(t *testing.T) {
	const relPath = "gitlab-runner-configs/config.toml"

	t.Run("missing config reports absent and registers on converge", func(t *testing.T) {
		registered := 0
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ProjectRoot:      t.TempDir(),
			RunnerConfigPath: relPath,
			RegisterGitLabGroupRunner: func(context.Context, ConvergeContext) error {
				registered++
				return nil
			},
		}), NodeCredentialsGitLabGroupRunner)
		assertInspectState(t, node, ObserveFast, StateAbsent)
		if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if registered != 1 {
			t.Errorf("RegisterGitLabGroupRunner calls = %d, want 1", registered)
		}
	})

	t.Run("empty config reports drifted and non-empty reports converged", func(t *testing.T) {
		root := t.TempDir()
		cfgPath := filepath.Join(root, relPath)
		writeTestFile(t, cfgPath, "   \n")
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ProjectRoot:      root,
			RunnerConfigPath: relPath,
		}), NodeCredentialsGitLabGroupRunner)
		assertInspectState(t, node, ObserveFast, StateDrifted)

		writeTestFile(t, cfgPath, "concurrent = 1\n")
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestCredentialSonarQubeAnalysisTokenNode(t *testing.T) {
	t.Run("missing vault token reports absent", func(t *testing.T) {
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap: func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
		}), NodeCredentialsSonarQubeAnalysisToken)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("vault token present without group variable reports drifted and converges", func(t *testing.T) {
		issued := 0
		var gotKey string
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap: readSonarAnalysisKV,
			VerifyGroupVariable: func(_ context.Context, key string) (bool, error) {
				gotKey = key
				return false, nil
			},
			IssueSonarQubeAnalysisToken: func(context.Context, ConvergeContext) error {
				issued++
				return nil
			},
		}), NodeCredentialsSonarQubeAnalysisToken)
		assertInspectState(t, node, ObserveFast, StateDrifted)
		if gotKey != "SONAR_TOKEN" {
			t.Errorf("VerifyGroupVariable key = %q, want SONAR_TOKEN", gotKey)
		}
		if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if issued != 1 {
			t.Errorf("IssueSonarQubeAnalysisToken calls = %d, want 1", issued)
		}
	})

	t.Run("vault token and group variable present reports converged", func(t *testing.T) {
		node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
			ReadKVMap:           readSonarAnalysisKV,
			VerifyGroupVariable: func(context.Context, string) (bool, error) { return true, nil },
		}), NodeCredentialsSonarQubeAnalysisToken)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestCredentialCodeReviewerVariablesNode(t *testing.T) {
	cases := []struct {
		name    string
		present int
		total   int
		want    NodeState
	}{
		{name: "none present reports absent", present: 0, total: 4, want: StateAbsent},
		{name: "partial present reports drifted", present: 2, total: 4, want: StateDrifted},
		{name: "all present reports converged", present: 4, total: 4, want: StateConverged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			published := 0
			node := findNodeByID(t, BuildCredentialNodes(CredentialObserverDeps{
				VerifyProjectVariables: func(context.Context) (int, int, error) {
					return tc.present, tc.total, nil
				},
				PublishCodeReviewerVariables: func(context.Context, ConvergeContext) error {
					published++
					return nil
				},
			}), NodeCredentialsCodeReviewerVariables)
			assertInspectState(t, node, ObserveFast, tc.want)
			if tc.want != StateConverged {
				if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
					t.Fatalf("Converge unexpected error: %v", err)
				}
				if published != 1 {
					t.Errorf("PublishCodeReviewerVariables calls = %d, want 1", published)
				}
			}
		})
	}
}

func TestBuildWorkstationGraphTopology(t *testing.T) {
	wantRootDeps := []string{
		NodeTerraformGroupGitLabConfiguration,
		NodeCredentialsGitLabGroupRunner,
		NodeCredentialsCodeReviewerVariables,
	}
	if got := DefaultRootHygieneDeps(); !slices.Equal(got, wantRootDeps) {
		t.Errorf("DefaultRootHygieneDeps() = %v, want %v", got, wantRootDeps)
	}

	graph, err := BuildWorkstationGraph(newFullPassWorkstationDeps(t.TempDir()))
	if err != nil {
		t.Fatalf("BuildWorkstationGraph unexpected error: %v", err)
	}
	order := graph.Order()
	if len(order) != 27 {
		t.Fatalf("graph node count = %d, want 27", len(order))
	}

	sub, err := graph.Subgraph(NodeTerraformFoundationVaultBastion)
	if err != nil {
		t.Fatalf("Subgraph(foundation_vault_bastion) unexpected error: %v", err)
	}
	if len(sub) != 13 {
		t.Errorf("Subgraph(foundation_vault_bastion) len = %d, want 13", len(sub))
	}
	for _, n := range sub {
		if n.Stage() > StageTrustRoot {
			t.Errorf("unexpected downstream node %s (stage %d) in Stage 0..3 subgraph", n.ID(), n.Stage())
		}
	}

	pos := indexOrderPositions(order)
	for _, dep := range wantRootDeps {
		if pos[dep] >= pos[NodeVaultRootHygiene] {
			t.Errorf("order %s (%d) >= %s (%d)", dep, pos[dep], NodeVaultRootHygiene, pos[NodeVaultRootHygiene])
		}
	}

	assertManualTokensBlocksDownstream(t)
}

func assertManualTokensBlocksDownstream(t *testing.T) {
	t.Helper()
	deps := newFullPassWorkstationDeps(t.TempDir())
	deps.Vault.ReadKVMap = func(_ context.Context, mount, path string) (map[string]string, bool, error) {
		if mount == "secret" && path == networkAllocationKVPath {
			return buildValidAllocationMap(), true, nil
		}
		return nil, false, nil
	}
	graph, err := BuildWorkstationGraph(deps)
	if err != nil {
		t.Fatalf("BuildWorkstationGraph unexpected error: %v", err)
	}
	reports, err := Observe(context.Background(), graph, ObserveFast, "")
	if err != nil {
		t.Fatalf("Observe unexpected error: %v", err)
	}
	byID := make(map[string]NodeReport, len(reports))
	for _, rep := range reports {
		byID[rep.ID] = rep
	}
	if byID[NodeVaultNetworkAllocation].State != StateConverged {
		t.Errorf("vault.network_allocation = %q, want CONVERGED", byID[NodeVaultNetworkAllocation].State)
	}
	for _, id := range []string{NodeVaultManualTokens, NodeTerraformFoundationVaultBastion, NodeHostTelemetry, NodeVaultRootHygiene} {
		if byID[id].State != StateBlocked {
			t.Errorf("%s State = %q, want BLOCKED", id, byID[id].State)
		}
	}
}

func newFullPassWorkstationDeps(root string) WorkstationDeps {
	return WorkstationDeps{
		Host: HostObserverDeps{
			ProjectRoot: root,
			Home:        root,
			LookPath:    func(file string) (string, error) { return "/usr/bin/" + file, nil },
			InspectContainers: func(context.Context) ([]ContainerState, error) {
				return buildContainerStates(coreContainers, true), nil
			},
			InspectSELinux:    convergedHostInspect,
			InspectLibvirt:    convergedHostInspect,
			InspectVaultProxy: convergedHostInspect,
			InspectVaultAudit: convergedHostInspect,
			InspectTelemetry:  convergedHostInspect,
		},
		Vault: VaultObserverDeps{
			ProjectRoot:     root,
			Home:            root,
			PublishIP:       "10.99.0.1",
			RootHygieneDeps: DefaultRootHygieneDeps(),
			InspectSealStatus: func(context.Context) vaultclient.SealStatus {
				return vaultclient.SealStatus{Reachable: true, Initialized: true, Sealed: false}
			},
			HasSecretMount:   func(context.Context) (bool, error) { return true, nil },
			ReadKVMap:        readAllConvergedVaultKV,
			VerifyAdminProxy: func(context.Context) (bool, error) { return true, nil },
		},
		Terraform: TerraformObserverDeps{
			ProjectRoot:          root,
			VerifyDirenvAllowed:  allowAllDirenv,
			HasOperatorCertMount: func(context.Context) (bool, error) { return true, nil },
			ReadKVMap:            readAllConvergedVaultKV,
			InspectLayerApplied:  func(context.Context, string) (bool, error) { return true, nil },
		},
		Credentials: CredentialObserverDeps{
			ProjectRoot:            root,
			RunnerConfigPath:       "gitlab-runner-configs/config.toml",
			ReadKVMap:              readAllConvergedVaultKV,
			VerifySonarQubeAdmin:   func(context.Context) (bool, error) { return true, nil },
			VerifyGroupVariable:    func(context.Context, string) (bool, error) { return true, nil },
			VerifyProjectVariables: func(context.Context) (int, int, error) { return 4, 4, nil },
		},
	}
}

func allowAllDirenv(context.Context, string) (bool, string, error) {
	return true, ".envrc", nil
}

func convergedHostInspect(context.Context, ObserveMode) (NodeState, string, error) {
	return StateConverged, "converged", nil
}

func readSonarAdminKV(_ context.Context, mount, path string) (map[string]string, bool, error) {
	if mount == "secret" && path == "parent-group-governance/sonarqube/admin-account" {
		return map[string]string{"sonarqube_admin_password": "example-password"}, true, nil
	}
	return nil, false, nil
}

func readSonarAnalysisKV(_ context.Context, mount, path string) (map[string]string, bool, error) {
	if mount == "secret" && path == "parent-group-governance/sonarqube/ci-analysis-bot" {
		return map[string]string{"sonarqube_ci_token": "example-ci-token"}, true, nil
	}
	return nil, false, nil
}

func readAllConvergedVaultKV(_ context.Context, mount, path string) (map[string]string, bool, error) {
	if mount == "secret" && path == networkAllocationKVPath {
		return buildValidAllocationMap(), true, nil
	}
	if mount == "secret" {
		return map[string]string{
			"token":                        "example-token",
			"anthropic_admin_api_key":      "example-admin-key",
			"anthropic_oauth_access_token": "example-oauth",
			"deploy_token":                 "example-deploy-token",
			"sonarqube_admin_password":     "example-admin-pass",
			"sonarqube_ci_token":           "example-ci-token",
		}, true, nil
	}
	if mount == "registry" {
		return map[string]string{"id": "example-registry-value"}, true, nil
	}
	return nil, false, nil
}

func indexOrderPositions(order []Node) map[string]int {
	pos := make(map[string]int, len(order))
	for i, n := range order {
		pos[n.ID()] = i
	}
	return pos
}
