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

// BastionVault is the listener topology of the Bastion Vault.
type BastionVault struct {
	LoopbackAddress string `yaml:"loopback_address"`
	PublishAddress  string `yaml:"publish_address"`
	Port            int    `yaml:"port"`
}

// ProxyIdentity is one operator identity of operator_proxy, whose Vault Proxy listens on the loopback at Port.
type ProxyIdentity struct {
	Port   int    `yaml:"port"`
	Access string `yaml:"access"`
}

// OperatorProxy is the part of operator_proxy which locates the Proxy of an identity and its client certificate.
type OperatorProxy struct {
	ConfigDir        string                   `yaml:"config_dir"`
	PlaceholderToken string                   `yaml:"placeholder_token"`
	Identities       map[string]ProxyIdentity `yaml:"identities"`
}

// ProxyEndpoint is the connection of a caller to the Vault Proxy of one identity.
type ProxyEndpoint struct {
	Identity   string
	Address    string
	CACert     string
	ClientCert string
	ClientKey  string
	Token      string
}

// Topology is the part of workstation-topology.yaml which this CLI reads.
type Topology struct {
	BastionVault  BastionVault  `yaml:"bastion_vault"`
	OperatorProxy OperatorProxy `yaml:"operator_proxy"`
}

// Load parses the topology file at path and rejects a Bastion Vault without both listener addresses and a port.
func Load(path string) (Topology, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Topology{}, fmt.Errorf("topology: read %s: %w", path, err)
	}
	var t Topology
	err = yaml.Unmarshal(data, &t)
	if err != nil {
		return Topology{}, fmt.Errorf("topology: parse %s: %w", path, err)
	}
	b := t.BastionVault
	if net.ParseIP(b.LoopbackAddress) == nil || net.ParseIP(b.PublishAddress) == nil {
		return Topology{}, fmt.Errorf("topology: %s: bastion_vault MUST declare loopback_address and publish_address as IP addresses", path)
	}
	if b.Port < 1 || b.Port > 65535 {
		return Topology{}, fmt.Errorf("topology: %s: bastion_vault.port %d is outside 1 to 65535", path, b.Port)
	}
	return t, nil
}

// Endpoint returns the loopback listener URL, which every operation of this CLI uses.
func (b BastionVault) Endpoint() string {
	return "https://" + net.JoinHostPort(b.LoopbackAddress, strconv.Itoa(b.Port))
}

// ListenerIPs returns the addresses which the listener certificate MUST carry as subject alternative names.
func (b BastionVault) ListenerIPs() []net.IP {
	return []net.IP{net.ParseIP(b.LoopbackAddress), net.ParseIP(b.PublishAddress)}
}

// AccessRole defines the operator proxy access level.
type AccessRole string

const (
	// AccessRoleFoundation identifies the operator proxy carrying foundation privileges.
	AccessRoleFoundation AccessRole = "foundation"
	// AccessRoleRotation identifies the operator proxy carrying credential rotation privileges.
	AccessRoleRotation AccessRole = "rotation"
)

// ResolveProxyEndpoint resolves the proxy connection parameters of the single identity with access role.
func (t Topology) ResolveProxyEndpoint(home string, role AccessRole) (ProxyEndpoint, error) {
	var names []string
	for name, identity := range t.OperatorProxy.Identities {
		if identity.Access == string(role) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		slices.Sort(names)
		return ProxyEndpoint{}, fmt.Errorf("topology: operator_proxy MUST declare exactly one identity with access %s, found %v", role, names)
	}
	name := names[0]
	base := filepath.Join(home, t.OperatorProxy.ConfigDir)
	return ProxyEndpoint{
		Identity:   name,
		Address:    "https://" + net.JoinHostPort(t.BastionVault.LoopbackAddress, strconv.Itoa(t.OperatorProxy.Identities[name].Port)),
		CACert:     filepath.Join(base, "ca.pem"),
		ClientCert: filepath.Join(base, name, "client.pem"),
		ClientKey:  filepath.Join(base, name, "client-key.pem"),
		Token:      t.OperatorProxy.PlaceholderToken,
	}, nil
}

// ProxyEndpoint preserves compatibility for callers passing string access categories.
func (t Topology) ProxyEndpoint(home, access string) (ProxyEndpoint, error) {
	return t.ResolveProxyEndpoint(home, AccessRole(access))
}
