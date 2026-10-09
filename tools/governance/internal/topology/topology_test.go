package topology

import (
	"net"
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

func TestLoad_DerivesEndpointAndListenerIPs(t *testing.T) {
	path := writeTopology(t, `bastion_vault:
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
	want := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("172.16.0.1")}
	if ips := got.BastionVault.ListenerIPs(); !slices.EqualFunc(ips, want, net.IP.Equal) {
		t.Errorf("ListenerIPs() = %v, want %v", ips, want)
	}
}

func TestLoad_RejectsIncompleteBastionVault(t *testing.T) {
	cases := map[string]string{
		"no publish address": "bastion_vault:\n  loopback_address: \"127.0.0.1\"\n  api_port: 8200\n",
		"hostname":           "bastion_vault:\n  loopback_address: \"localhost\"\n  publish_address: \"172.16.0.1\"\n  api_port: 8200\n",
		"no api port":        "bastion_vault:\n  loopback_address: \"127.0.0.1\"\n  publish_address: \"172.16.0.1\"\n",
		"port out of range":  "bastion_vault:\n  loopback_address: \"127.0.0.1\"\n  publish_address: \"172.16.0.1\"\n  api_port: 70000\n",
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

func TestLoad_FailsWithoutFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), FileName))
	if err == nil {
		t.Error("Load error = nil, want a failure on a missing topology file")
	}
}

func TestLoad_RejectsMalformedYAML(t *testing.T) {
	_, err := Load(writeTopology(t, "bastion_vault: [unterminated\n"))
	if err == nil {
		t.Error("Load error = nil, want a parse failure")
	}
}

func TestResolveProxyEndpoint_LocatesTheIdentityOfAnAccess(t *testing.T) {
	path := writeTopology(t, `bastion_vault:
  loopback_address: "127.0.0.1"
  publish_address: "172.16.0.1"
  api_port: 8200
operator_vault_proxy:
  user_config_dir: ".config/vault-proxy"
  placeholder_token: "proxy-supplied"
  identities:
    governance:
      listen_port: 8210
      access_tier: "governance"
    service-admin-passwords:
      listen_port: 8213
      access_tier: "rotation"
`)
	topo, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, err := topo.ResolveProxyEndpoint("/home/u", AccessRoleRotation)
	if err != nil {
		t.Fatalf("ResolveProxyEndpoint: %v", err)
	}
	want := ProxyEndpoint{
		Identity:   "service-admin-passwords",
		Address:    "https://127.0.0.1:8213",
		CACert:     "/home/u/.config/vault-proxy/ca.pem",
		ClientCert: "/home/u/.config/vault-proxy/service-admin-passwords/client.pem",
		ClientKey:  "/home/u/.config/vault-proxy/service-admin-passwords/client-key.pem",
		Token:      "proxy-supplied",
	}
	if got != want {
		t.Errorf("ResolveProxyEndpoint = %+v, want %+v", got, want)
	}
}

func TestResolveProxyEndpoint_RequiresExactlyOneIdentity(t *testing.T) {
	topo := VaultTopology{OperatorVaultProxy: OperatorVaultProxy{Identities: map[string]ProxyIdentity{
		"first":  {ListenPort: 1, AccessTier: "rotation"},
		"second": {ListenPort: 2, AccessTier: "rotation"},
	}}}
	for _, access := range []AccessRole{AccessRoleRotation, AccessRoleFoundation} {
		if _, err := topo.ResolveProxyEndpoint("/home/u", access); err == nil {
			t.Errorf("ResolveProxyEndpoint(%s) error = nil, want a rejection", access)
		}
	}
}
