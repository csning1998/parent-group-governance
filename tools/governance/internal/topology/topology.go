// Package topology loads workstation-topology.yaml, which Ansible, Terraform, and this CLI share.
package topology

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"
)

// FileName is the topology file below the project root.
const FileName = "workstation-topology.yaml"

// AccessRole defines the operator proxy access level.
type AccessRole string

const (
	// AccessRoleFoundation identifies the operator proxy carrying foundation privileges.
	AccessRoleFoundation AccessRole = "foundation"
	// AccessRoleRotation identifies the operator proxy carrying credential rotation privileges.
	AccessRoleRotation AccessRole = "rotation"
)

// BastionVault is the listener topology of the Bastion Vault server.
type BastionVault struct {
	LoopbackAddress string `yaml:"loopback_address"` // host loopback address (127.0.0.1) for local processes
	PublishAddress  string `yaml:"publish_address"`  // hypervisor bridge address (172.16.0.1) for guest VM / runner access
	APIPort         int    `yaml:"api_port"`         // primary HTTPS API port bound by Vault daemon (8200)
	ClusterPort     int    `yaml:"cluster_port"`     // Raft cluster request forwarding and HA interconnect port (8201)
	MetricsPort     int    `yaml:"metrics_port"`     // unauthenticated Prometheus metrics telemetry scraping port (8202)
}

// APIEndpoint returns the loopback API listener URL (e.g. https://127.0.0.1:8200), which CLI operations use.
func (b BastionVault) APIEndpoint() string {
	return "https://" + net.JoinHostPort(b.LoopbackAddress, strconv.Itoa(b.APIPort))
}

// ListenerIPs returns the addresses which the listener certificate MUST carry as subject alternative names.
func (b BastionVault) ListenerIPs() []net.IP {
	return []net.IP{net.ParseIP(b.LoopbackAddress), net.ParseIP(b.PublishAddress)}
}

// ProxyIdentity defines one operator proxy instance listening on loopback and mapping to a Vault cert role.
type ProxyIdentity struct {
	ListenPort int    `yaml:"listen_port"` // local TCP port on 127.0.0.1 bound by this proxy instance (e.g. 8210)
	AccessTier string `yaml:"access_tier"` // logical privilege tier of the operator role (governance, tenant, foundation, rotation)
}

// OperatorVaultProxy holds client connection parameters and identity mappings for operator Vault proxies.
type OperatorVaultProxy struct {
	CertAuthMount    string                   `yaml:"cert_auth_mount"`   // Vault TLS certificate auth mount path matching CN operator-<identity>
	UserConfigDir    string                   `yaml:"user_config_dir"`   // directory relative to user $HOME storing mTLS client certs and systemd units
	PlaceholderToken string                   `yaml:"placeholder_token"` // dummy token string required by client headers; stripped and replaced by proxy
	Identities       map[string]ProxyIdentity `yaml:"identities"`        // operator role entries mapped to their local listener ports and tiers
}

// ProxyEndpoint holds the client connection parameters required to communicate with a local operator Vault Proxy.
type ProxyEndpoint struct {
	Identity   string // operator proxy identity name (e.g. governance, rotation, foundation)
	Address    string // loopback HTTPS URL of the local proxy listener (e.g. https://127.0.0.1:8210)
	CACert     string // absolute filesystem path to local root CA certificate bundle (ca.pem)
	ClientCert string // absolute filesystem path to operator mTLS client certificate (client.pem)
	ClientKey  string // absolute filesystem path to operator mTLS client private key (client-key.pem)
	Token      string // dummy placeholder token (proxy-supplied); proxy replaces it via mTLS
}

// VaultTopology represents the Bastion Vault and operator proxy network endpoints declared in workstation-topology.yaml.
type VaultTopology struct {
	BastionVault       BastionVault       `yaml:"bastion_vault"`        // Bastion Vault network listener bindings
	OperatorVaultProxy OperatorVaultProxy `yaml:"operator_vault_proxy"` // local operator mTLS proxies configuration
}

// ResolveProxyEndpoint resolves the proxy connection parameters of the single identity with access role.
func (v VaultTopology) ResolveProxyEndpoint(home string, role AccessRole) (ProxyEndpoint, error) {
	var names []string
	for name, identity := range v.OperatorVaultProxy.Identities {
		if identity.AccessTier == string(role) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		slices.Sort(names)
		return ProxyEndpoint{}, fmt.Errorf("topology: operator_vault_proxy MUST declare exactly one identity with access_tier %s, found %v", role, names)
	}
	name := names[0]
	base := filepath.Join(home, v.OperatorVaultProxy.UserConfigDir)
	return ProxyEndpoint{
		Identity:   name,
		Address:    "https://" + net.JoinHostPort(v.BastionVault.LoopbackAddress, strconv.Itoa(v.OperatorVaultProxy.Identities[name].ListenPort)),
		CACert:     filepath.Join(base, "ca.pem"),
		ClientCert: filepath.Join(base, name, "client.pem"),
		ClientKey:  filepath.Join(base, name, "client-key.pem"),
		Token:      v.OperatorVaultProxy.PlaceholderToken,
	}, nil
}

// Load parses the workstation topology file at path and validates Bastion Vault network listener settings.
func Load(path string) (VaultTopology, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return VaultTopology{}, fmt.Errorf("topology: read %s: %w", path, err)
	}
	var v VaultTopology
	err = yaml.Unmarshal(data, &v)
	if err != nil {
		return VaultTopology{}, fmt.Errorf("topology: parse %s: %w", path, err)
	}
	b := v.BastionVault
	if net.ParseIP(b.LoopbackAddress) == nil || net.ParseIP(b.PublishAddress) == nil {
		return VaultTopology{}, fmt.Errorf("topology: %s: bastion_vault MUST declare loopback_address and publish_address as IP addresses", path)
	}
	if b.APIPort < 1 || b.APIPort > 65535 {
		return VaultTopology{}, fmt.Errorf("topology: %s: bastion_vault.api_port %d is outside 1 to 65535", path, b.APIPort)
	}
	return v, nil
}
