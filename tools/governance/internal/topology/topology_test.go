package topology

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeTopology(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), FileName)
	err := os.WriteFile(path, []byte(content), 0o600)
	if err != nil {
		t.Fatalf("write topology: %v", err)
	}
	return path
}

func TestLoadDerivesEndpoint(t *testing.T) {
	path := writeTopology(t, `vault_bastion:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
operator_vault_proxy:
  cert_auth_mount: "operator-cert"
`)
	got, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if endpoint := got.BastionVault.APIEndpoint(); endpoint != "https://127.0.0.1:8200" {
		t.Errorf("APIEndpoint() = %q, want https://127.0.0.1:8200", endpoint)
	}
}

func TestLoadRejectsIncompleteBastionVault(t *testing.T) {
	cases := map[string]string{
		"no publish address": "vault_bastion:\n  loopback_address: \"127.0.0.1\"\n  api_port: 8200\n",
		"hostname":           "vault_bastion:\n  loopback_address: \"localhost\"\n  publish_address: \"172.16.0.1\"\n  api_port: 8200\n",
		"no api port":        "vault_bastion:\n  loopback_address: \"127.0.0.1\"\n  publish_address: \"172.16.0.1\"\n",
		"port out of range":  "vault_bastion:\n  loopback_address: \"127.0.0.1\"\n  publish_address: \"172.16.0.1\"\n  api_port: 70000\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Load(writeTopology(t, content))
			if err == nil {
				t.Errorf("Load error = nil, want a rejection of %s", name)
			}
		})
	}
}

func TestLoadFailsWithoutFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), FileName))
	if err == nil {
		t.Error("Load error = nil, want a failure on a missing topology file")
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	_, err := Load(writeTopology(t, "vault_bastion: [unterminated\n"))
	if err == nil {
		t.Error("Load error = nil, want a parse failure")
	}
}

func TestResolveProxyEndpointLocatesTheIdentityOfAnAccess(t *testing.T) {
	path := writeTopology(t, `vault_bastion:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
operator_vault_proxy:
  user_config_dir: ".config/vault-proxy"
  placeholder_token: "proxy-supplied"
  identities:
    credential-distributor-example-governance:
      listen_port: 8210
    credential-rotator:
      listen_port: 8213
`)
	topo, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := topo.ResolveProxyEndpoint("/home/u", AccessRoleCredentialRotator)
	if err != nil {
		t.Fatalf("ResolveProxyEndpoint: %v", err)
	}
	want := ProxyEndpoint{
		Identity:   "credential-rotator",
		Address:    "https://127.0.0.1:8213",
		CACert:     "/home/u/.config/vault-proxy/ca.pem",
		ClientCert: "/home/u/.config/vault-proxy/credential-rotator/client.pem",
		ClientKey:  "/home/u/.config/vault-proxy/credential-rotator/client-key.pem",
		Token:      "proxy-supplied",
	}
	if got != want {
		t.Errorf("ResolveProxyEndpoint = %+v, want %+v", got, want)
	}
}

func TestResolveProxyEndpointRequiresTheIdentityOfTheAccess(t *testing.T) {
	topo := VaultTopology{OperatorVaultProxy: OperatorVaultProxy{Identities: map[string]ProxyIdentity{
		"credential-distributor-example-governance": {ListenPort: 1},
		"example-tenant": {ListenPort: 2},
	}}}
	for _, access := range []AccessRole{AccessRoleCredentialRotator, AccessRoleAdministrator} {
		if _, err := topo.ResolveProxyEndpoint("/home/u", access); err == nil {
			t.Errorf("ResolveProxyEndpoint(%s) error = nil, want a rejection", access)
		}
	}
}

// stateBackendTopology defines fixture topology containing distributor and consumer identities of two owners.
const stateBackendTopology = `vault_bastion:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
operator_vault_proxy:
  governance_owner_code: "example-governance"
  state_backend:
    vault_kv_mount: "secret"
    vault_kv_field: "token"
  identities:
    credential-distributor-example-governance: {}
    consumer-example-governance: {}
    credential-distributor-example-tenant: {}
`

// TestListCodeReviewerVariableProjects asserts byte-order sorting and deduplication across configured project paths.
func TestListCodeReviewerVariableProjects(t *testing.T) {
	topo, err := Load(writeTopology(t, `vault_bastion:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
operator_vault_proxy:
  identities:
    credential-distributor-personal:
      code_reviewer_variable_projects: ["example-subgroup/project-b", "example-subgroup/Project_A"]
    credential-distributor-example-governance:
      code_reviewer_variable_projects: ["example-governance", "example-subgroup/project-b"]
    administrator: {}
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"example-group/example-governance", "example-group/example-subgroup/Project_A", "example-group/example-subgroup/project-b"}
	if got := topo.ListCodeReviewerVariableProjects("example-group"); !slices.Equal(got, want) {
		t.Errorf("ListCodeReviewerVariableProjects() = %v, want %v", got, want)
	}
}

// TestResolveIdentityRole asserts the access tier, owner code, and state backend path determined by the identity name.
func TestResolveIdentityRole(t *testing.T) {
	proxy := OperatorVaultProxy{GovernanceOwnerCode: "example-governance"}
	cases := map[string]IdentityRole{
		"administrator":                         {AccessTier: "administrator", OwnerCode: "example-governance", StateBackendPath: "example-governance/terraform/state-backend"},
		"credential-rotator":                    {AccessTier: "credential-rotator", OwnerCode: "example-governance"},
		"credential-distributor-example-tenant": {AccessTier: "credential-distributor", OwnerCode: "example-tenant", StateBackendPath: "example-tenant/terraform/state-backend"},
		"consumer-example-tenant":               {AccessTier: "consumer", OwnerCode: "example-tenant", StateBackendPath: "example-tenant/terraform/state-backend"},
		"example-tenant":                        {AccessTier: "tenant", OwnerCode: "example-tenant", StateBackendPath: "example-tenant/terraform/state-backend"},
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			if got := proxy.ResolveIdentityRole(name); got != want {
				t.Errorf("ResolveIdentityRole(%s) = %+v, want %+v", name, got, want)
			}
		})
	}
}

// TestResolveStateBackendToken asserts the token location of a distributor and the rejection of an owner code without a distributor path.
func TestResolveStateBackendToken(t *testing.T) {
	topo, err := Load(writeTopology(t, stateBackendTopology))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cases := map[string]struct {
		ownerCode string
		want      KVField
		wantErr   bool
	}{
		"the governance distributor": {
			ownerCode: "example-governance",
			want:      KVField{Mount: "secret", Path: "example-governance/terraform/state-backend", Field: "token"},
		},
		"the distributor of another owner": {
			ownerCode: "example-tenant",
			want:      KVField{Mount: "secret", Path: "example-tenant/terraform/state-backend", Field: "token"},
		},
		"an owner code without a distributor": {ownerCode: "example-absent", wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := topo.ResolveStateBackendToken(tc.ownerCode)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ResolveStateBackendToken(%s) error = %v, want an error %t", tc.ownerCode, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("ResolveStateBackendToken(%s) = %+v, want %+v", tc.ownerCode, got, tc.want)
			}
		})
	}
}
