package converge

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func TestHostToolsNodeInspect(t *testing.T) {
	t.Run("all required binaries present", func(t *testing.T) {
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{
			LookPath: func(file string) (string, error) { return "/usr/bin/" + file, nil },
		}), NodeHostTools)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})

	t.Run("missing direnv and podman blocks with hint", func(t *testing.T) {
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{
			LookPath: func(file string) (string, error) {
				if file == "direnv" || file == "podman" {
					return "", errors.New("not found")
				}
				return "/usr/bin/" + file, nil
			},
		}), NodeHostTools)
		rep := assertInspectState(t, node, ObserveFast, StateBlocked)
		assertHintContains(t, rep, "direnv", "podman")
	})
}

func TestHostEnvFileNodeInspect(t *testing.T) {
	t.Run("missing env file reports absent", func(t *testing.T) {
		root := t.TempDir()
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostEnvFile)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("missing db password with non-empty postgres data blocks", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, ".env"), "PROJECT_ROOT="+root+"\nHOST_UID=1000\nHOST_GID=1000\nUNAME=op\nUHOME=/home/op\n")
		writeTestFile(t, filepath.Join(root, "sonarqube", "postgres-data", "PG_VERSION"), "17\n")
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostEnvFile)
		assertInspectState(t, node, ObserveFast, StateBlocked)
	})

	t.Run("missing non-db key reports drifted", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, ".env"), "PROJECT_ROOT="+root+"\nHOST_GID=1000\nUNAME=op\nUHOME=/home/op\nSONARQUBE_DB_PASSWORD=secret\n")
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostEnvFile)
		assertInspectState(t, node, ObserveFast, StateDrifted)
	})

	t.Run("all six keys present reports converged", func(t *testing.T) {
		root := t.TempDir()
		writeTestFile(t, filepath.Join(root, ".env"), "PROJECT_ROOT="+root+"\nHOST_UID=1000\nHOST_GID=1000\nUNAME=op\nUHOME=/home/op\nSONARQUBE_DB_PASSWORD=secret\n")
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostEnvFile)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestHostTLSCANodeInspect(t *testing.T) {
	tlsNames := []string{"ca-ml-dsa-87", "ca-ec-p384", "loopback", "publish", "terminator-client"}

	t.Run("missing tls directory reports absent", func(t *testing.T) {
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: t.TempDir()}), NodeHostTLSCA)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("missing terminator cert reports drifted", func(t *testing.T) {
		root := t.TempDir()
		writeTLSPairs(t, root, tlsNames[:4])
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostTLSCA)
		assertInspectState(t, node, ObserveFast, StateDrifted)
	})

	t.Run("all five cert and key pairs present reports converged", func(t *testing.T) {
		root := t.TempDir()
		writeTLSPairs(t, root, tlsNames)
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{ProjectRoot: root}), NodeHostTLSCA)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestContainerCoreNodeInspect(t *testing.T) {
	coreNames := []string{
		"parent-group-governance-vault-bastion",
		"parent-group-governance-vault-bastion-terminator",
		"parent-group-governance-sonarqube-postgres",
		"parent-group-governance-sonarqube",
		"parent-group-governance-gitlab-runner",
	}

	t.Run("zero running reports absent", func(t *testing.T) {
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{
			InspectContainers: func(context.Context) ([]ContainerState, error) { return nil, nil },
		}), NodeContainerCore)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("partial or unhealthy reports drifted", func(t *testing.T) {
		states := buildContainerStates(coreNames, false)
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{
			InspectContainers: func(context.Context) ([]ContainerState, error) { return states, nil },
		}), NodeContainerCore)
		assertInspectState(t, node, ObserveFast, StateDrifted)
	})

	t.Run("all five running and healthy reports converged", func(t *testing.T) {
		states := buildContainerStates(coreNames, true)
		node := findNodeByID(t, BuildHostNodes(HostObserverDeps{
			InspectContainers: func(context.Context) ([]ContainerState, error) { return states, nil },
		}), NodeContainerCore)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestVaultInitializedUnsealedAndKVNodes(t *testing.T) {
	t.Run("unreachable blocks vault.initialized", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot:       t.TempDir(),
			InspectSealStatus: func(context.Context) vaultclient.SealStatus { return vaultclient.SealStatus{Reachable: false} },
		}), NodeVaultInitialized)
		assertInspectState(t, node, ObserveFast, StateBlocked)
	})

	t.Run("uninitialized with rejected factory default blocks", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot: t.TempDir(),
			InspectSealStatus: func(context.Context) vaultclient.SealStatus {
				return vaultclient.SealStatus{Reachable: true, Initialized: false, Sealed: true}
			},
			VerifyFactoryDefault: func(context.Context) (bool, string, error) { return false, "sonarqube-admin-password", nil },
		}), NodeVaultInitialized)
		assertInspectState(t, node, ObserveFast, StateBlocked)
	})

	t.Run("uninitialized with accepted factory default reports absent", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot: t.TempDir(),
			InspectSealStatus: func(context.Context) vaultclient.SealStatus {
				return vaultclient.SealStatus{Reachable: true, Initialized: false, Sealed: true}
			},
			VerifyFactoryDefault: func(context.Context) (bool, string, error) { return true, "", nil },
		}), NodeVaultInitialized)
		assertInspectState(t, node, ObserveFast, StateAbsent)
	})

	t.Run("initialized sealed with and without unseal.key", func(t *testing.T) {
		rootWithKey := t.TempDir()
		writeTestFile(t, filepath.Join(rootWithKey, "vault", "keys", "unseal.key"), "key1\n")
		depsWithKey := VaultObserverDeps{
			ProjectRoot: rootWithKey,
			InspectSealStatus: func(context.Context) vaultclient.SealStatus {
				return vaultclient.SealStatus{Reachable: true, Initialized: true, Sealed: true}
			},
		}
		assertInspectState(t, findNodeByID(t, BuildVaultNodes(depsWithKey), NodeVaultInitialized), ObserveFast, StateConverged)
		assertInspectState(t, findNodeByID(t, BuildVaultNodes(depsWithKey), NodeVaultUnsealed), ObserveFast, StateDrifted)

		depsNoKey := VaultObserverDeps{
			ProjectRoot: t.TempDir(),
			InspectSealStatus: func(context.Context) vaultclient.SealStatus {
				return vaultclient.SealStatus{Reachable: true, Initialized: true, Sealed: true}
			},
		}
		assertInspectState(t, findNodeByID(t, BuildVaultNodes(depsNoKey), NodeVaultUnsealed), ObserveFast, StateBlocked)
	})

	t.Run("unsealed checks secret mount", func(t *testing.T) {
		for _, mounted := range []bool{false, true} {
			want := StateAbsent
			if mounted {
				want = StateConverged
			}
			node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
				ProjectRoot: t.TempDir(),
				InspectSealStatus: func(context.Context) vaultclient.SealStatus {
					return vaultclient.SealStatus{Reachable: true, Initialized: true, Sealed: false}
				},
				HasSecretMount: func(context.Context) (bool, error) { return mounted, nil },
			}), NodeVaultKVSecret)
			assertInspectState(t, node, ObserveFast, want)
		}
	})
}

func TestVaultNetworkAllocationNodeInspectAndConverge(t *testing.T) {
	validMap := buildValidAllocationMap()

	t.Run("valid Vault map reports converged", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot: t.TempDir(),
			PublishIP:   "10.99.0.1",
			ReadKVMap:   func(context.Context, string, string) (map[string]string, bool, error) { return validMap, true, nil },
		}), NodeVaultNetworkAllocation)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})

	t.Run("missing Vault map and missing local JSON blocks", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot: t.TempDir(),
			PublishIP:   "10.99.0.1",
			ReadKVMap:   func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
		}), NodeVaultNetworkAllocation)
		assertInspectState(t, node, ObserveFast, StateBlocked)
	})

	t.Run("missing Vault map with valid local JSON reports absent and converges", func(t *testing.T) {
		root := t.TempDir()
		raw, err := json.Marshal(validMap)
		if err != nil {
			t.Fatalf("marshal valid allocation: %v", err)
		}
		writeTestFile(t, filepath.Join(root, "network-allocation.json"), string(raw))

		var writtenMount, writtenPath string
		var writtenData map[string]string
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ProjectRoot: root,
			PublishIP:   "10.99.0.1",
			ReadKVMap:   func(context.Context, string, string) (map[string]string, bool, error) { return nil, false, nil },
			WriteKVMap: func(_ context.Context, mount, path string, data map[string]string) error {
				writtenMount, writtenPath, writtenData = mount, path, data
				return nil
			},
		}), NodeVaultNetworkAllocation)
		assertInspectState(t, node, ObserveFast, StateAbsent)
		if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if writtenMount != "secret" || writtenPath != "parent-group-governance/network/allocation" || !maps.Equal(writtenData, validMap) {
			t.Errorf("WriteKVMap = (%q, %q, %v), want (secret, parent-group-governance/network/allocation, validMap)", writtenMount, writtenPath, writtenData)
		}
	})
}

func TestVaultManualTokensNodeObserveOnly(t *testing.T) {
	reqs := RequiredManualTokens()
	if len(reqs) != 6 {
		t.Fatalf("RequiredManualTokens count = %d, want 6", len(reqs))
	}

	t.Run("missing two tokens blocks with vault kv put hints", func(t *testing.T) {
		writes := 0
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ReadKVMap: func(_ context.Context, _, path string) (map[string]string, bool, error) {
				if path == reqs[0].Path || path == reqs[1].Path {
					return nil, false, nil
				}
				return map[string]string{fieldForPath(reqs, path): "example-token"}, true, nil
			},
			WriteKVMap: func(context.Context, string, string, map[string]string) error {
				writes++
				return nil
			},
		}), NodeVaultManualTokens)
		rep := assertInspectState(t, node, ObserveFast, StateBlocked)
		assertHintContains(t, rep, "vault kv put", reqs[0].Path, reqs[1].Path)
		if err := node.Converge(context.Background(), ConvergeContext{}); err == nil && writes != 0 {
			t.Errorf("manual token node wrote %d times, want 0", writes)
		}
	})

	t.Run("all six tokens present reports converged", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			ReadKVMap: func(_ context.Context, _, path string) (map[string]string, bool, error) {
				return map[string]string{fieldForPath(reqs, path): "example-token"}, true, nil
			},
		}), NodeVaultManualTokens)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})
}

func TestVaultRootHygieneNodeInspect(t *testing.T) {
	t.Run("admin active and root token absent reports converged", func(t *testing.T) {
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			Home:             t.TempDir(),
			VerifyAdminProxy: func(context.Context) (bool, error) { return true, nil },
		}), NodeVaultRootHygiene)
		assertInspectState(t, node, ObserveFast, StateConverged)
	})

	t.Run("present root token reports drifted and revokes on converge", func(t *testing.T) {
		home := t.TempDir()
		writeTestFile(t, filepath.Join(home, ".vault-token"), "hvs.example-root")
		revoked := 0
		node := findNodeByID(t, BuildVaultNodes(VaultObserverDeps{
			Home:             home,
			VerifyAdminProxy: func(context.Context) (bool, error) { return true, nil },
			RevokeRootToken:  func(context.Context, ConvergeContext) error { revoked++; return nil },
		}), NodeVaultRootHygiene)
		assertInspectState(t, node, ObserveFast, StateDrifted)
		if err := node.Converge(context.Background(), ConvergeContext{}); err != nil {
			t.Fatalf("Converge unexpected error: %v", err)
		}
		if revoked != 1 {
			t.Errorf("RevokeRootToken calls = %d, want 1", revoked)
		}
	})
}

func findNodeByID(t *testing.T, nodes []Node, id string) Node {
	t.Helper()
	for _, n := range nodes {
		if n.ID() == id {
			return n
		}
	}
	t.Fatalf("node %q missing from slice of %d nodes", id, len(nodes))
	return nil
}

func assertInspectState(t *testing.T, node Node, mode ObserveMode, want NodeState) NodeReport {
	t.Helper()
	rep, err := node.Inspect(context.Background(), mode)
	if err != nil {
		t.Fatalf("%s Inspect unexpected error: %v", node.ID(), err)
	}
	if rep.State != want {
		t.Errorf("%s State = %q, want %q (summary=%q hint=%q)", node.ID(), rep.State, want, rep.Summary, rep.Hint)
	}
	return rep
}

func assertHintContains(t *testing.T, rep NodeReport, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(rep.Hint, p) {
			t.Errorf("%s Hint = %q, want substring %q", rep.ID, rep.Hint, p)
		}
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeTLSPairs(t *testing.T, root string, names []string) {
	t.Helper()
	for _, name := range names {
		writeTestFile(t, filepath.Join(root, "vault", "tls", name+".pem"), "cert")
		writeTestFile(t, filepath.Join(root, "vault", "tls", name+"-key.pem"), "key")
	}
}

func buildContainerStates(names []string, healthy bool) []ContainerState {
	states := make([]ContainerState, len(names))
	for i, name := range names {
		states[i] = ContainerState{Name: name, Running: true, Healthy: healthy}
	}
	return states
}

func buildValidAllocationMap() map[string]string {
	return map[string]string{
		"domain_suffix":        "foo-bar.example",
		"stages":               `["foo-bar"]`,
		"network_cidr":         "10.99.0.0/16",
		"bastion_publish_cidr": "10.99.0.0/24",
		"pod_network_cidr":     "10.192.0.0/10",
		"service_network_cidr": "100.64.0.0/12",
		"network_baseline":     `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":248}`,
	}
}

func fieldForPath(reqs []ManualTokenRequirement, path string) string {
	for _, r := range reqs {
		if r.Path == path {
			return r.Field
		}
	}
	return ""
}
