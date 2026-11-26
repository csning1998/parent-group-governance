// Package topology loads workstation-topology.yaml shared by Ansible, Terraform, and this CLI.
package topology

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileName is the topology file below the project root.
const FileName = "workstation-topology.yaml"

// AccessRole defines the operator proxy access level.
type AccessRole string

const (
	// AccessRoleAdministrator identifies the operator proxy with administrator privileges.
	AccessRoleAdministrator AccessRole = "administrator"
	// AccessRoleCredentialRotator identifies the operator proxy with credential rotation privileges.
	AccessRoleCredentialRotator AccessRole = "credential-rotator"
)

const (
	accessTierCredentialDistributor = "credential-distributor"
	accessTierConsumer              = "consumer"
	accessTierTenant                = "tenant"
)

// BastionVault is the listener topology of the Bastion Vault server.
type BastionVault struct {
	LoopbackIP  string `yaml:"loopback_ip"`
	PublishIP   string `yaml:"publish_ip"`
	APIPort     int    `yaml:"api_port"`
	ClusterPort int    `yaml:"cluster_port"`
	MetricsPort int    `yaml:"metrics_port"`
}

// APIEndpoint returns the loopback API listener URL (e.g. https://127.0.0.1:8200) used by CLI operations.
func (b BastionVault) APIEndpoint() string {
	return "https://" + net.JoinHostPort(b.LoopbackIP, strconv.Itoa(b.APIPort))
}

// ProxyIdentity defines one operator proxy instance listening on loopback and mapping to a Vault cert role.
type ProxyIdentity struct {
	ListenPort int `yaml:"listen_port"`

	// CodeReviewerVariableProjects lists project paths relative to the top level group.
	CodeReviewerVariableProjects []string `yaml:"code_reviewer_variable_projects"`
}

// IdentityRole contains the access tier, owner code, and KV v2 state token path derived from an identity name.
type IdentityRole struct {
	AccessTier string
	OwnerCode  string
	// Empty for credential-rotator because the rotator identity does not run Terraform.
	StateBackendPath string
}

// ResolveIdentityRole derives the access tier, owner code, and state token path from the identity naming convention
// defined in workstation-topology-specification.md.
func (o OperatorVaultProxy) ResolveIdentityRole(name string) IdentityRole {
	role := IdentityRole{AccessTier: accessTierTenant, OwnerCode: name}
	switch {
	case name == string(AccessRoleAdministrator) || name == string(AccessRoleCredentialRotator):
		role = IdentityRole{AccessTier: name, OwnerCode: o.GovernanceOwnerCode}
	case strings.HasPrefix(name, accessTierCredentialDistributor+"-"):
		role = IdentityRole{AccessTier: accessTierCredentialDistributor, OwnerCode: strings.TrimPrefix(name, accessTierCredentialDistributor+"-")}
	case strings.HasPrefix(name, accessTierConsumer+"-"):
		role = IdentityRole{AccessTier: accessTierConsumer, OwnerCode: strings.TrimPrefix(name, accessTierConsumer+"-")}
	}
	if role.AccessTier != string(AccessRoleCredentialRotator) {
		role.StateBackendPath = role.OwnerCode + "/terraform/state-backend"
	}
	return role
}

// ListCodeReviewerVariableProjects returns sorted and deduplicated full project paths prefixed with topLevelGroup.
func (v VaultTopology) ListCodeReviewerVariableProjects(topLevelGroup string) []string {
	var paths []string
	for _, identity := range v.OperatorVaultProxy.Identities {
		for _, project := range identity.CodeReviewerVariableProjects {
			paths = append(paths, topLevelGroup+"/"+project)
		}
	}
	slices.Sort(paths)
	return slices.Compact(paths)
}

// StateBackend defines the shared KV v2 mount and field schema across state backend paths.
type StateBackend struct {
	VaultKVMount string `yaml:"vault_kv_mount"`
	VaultKVField string `yaml:"vault_kv_field"`
}

// OperatorVaultProxy contains client connection parameters and identity mappings for operator Vault proxies.
type OperatorVaultProxy struct {
	GovernanceOwnerCode string `yaml:"governance_owner_code"`

	CertAuthMount string `yaml:"cert_auth_mount"`
	// Relative to $HOME.
	UserConfigDir string `yaml:"user_config_dir"`
	// Replaced by the local proxy over mTLS.
	PlaceholderToken string                   `yaml:"placeholder_token"`
	StateBackend     StateBackend             `yaml:"state_backend"`
	Identities       map[string]ProxyIdentity `yaml:"identities"`
}

// KVField specifies the location of a single field within a KV v2 secret.
type KVField struct {
	Mount string
	Path  string
	Field string
}

// ResolveStateBackendToken returns the KV v2 location of the GitLab token for the given ownerCode distributor.
func (v VaultTopology) ResolveStateBackendToken(ownerCode string) (KVField, error) {
	var paths []string
	for name := range v.OperatorVaultProxy.Identities {
		role := v.OperatorVaultProxy.ResolveIdentityRole(name)
		if role.AccessTier == accessTierCredentialDistributor && role.OwnerCode == ownerCode {
			paths = append(paths, role.StateBackendPath)
		}
	}
	if len(paths) != 1 {
		return KVField{}, fmt.Errorf("topology: operator_vault_proxy requires identity %s-%s, found %d", accessTierCredentialDistributor, ownerCode, len(paths))
	}
	backend := v.OperatorVaultProxy.StateBackend
	return KVField{Mount: backend.VaultKVMount, Path: paths[0], Field: backend.VaultKVField}, nil
}

// ProxyEndpoint contains connection parameters for a local operator Vault Proxy.
type ProxyEndpoint struct {
	Identity   string
	Address    string
	CACert     string
	ClientCert string
	ClientKey  string
	// Replaced by the local proxy via mTLS.
	Token string
}

// HostTelemetryRegistry specifies the Vault KV v2 coordinates of the scrape subnet published by foundation-vault-bastion.
type HostTelemetryRegistry struct {
	Mount     string `yaml:"vault_kv_mount"`
	Path      string `yaml:"vault_kv_path"`
	CIDRField string `yaml:"cidr_field"`
	IPField   string `yaml:"ip_field"`
}

// HostTelemetryScrape contains the Vault registry reference and host collector directory for telemetry.
type HostTelemetryScrape struct {
	Registry             HostTelemetryRegistry `yaml:"registry"`
	TextfileCollectorDir string                `yaml:"textfile_collector_dir"`
}

// HostLogRendezvousRegistry specifies the Vault KV v2 coordinates of the segment 250 log rendezvous.
type HostLogRendezvousRegistry struct {
	Mount            string `yaml:"vault_kv_mount"`
	Path             string `yaml:"vault_kv_path"`
	CIDRField        string `yaml:"cidr_field"`
	IPField          string `yaml:"ip_field"`
	ServerNamesField string `yaml:"server_names_field"`
}

// HostLogRendezvous configures Bastion Vault server log shipping over segment 250 to Loki.
type HostLogRendezvous struct {
	NetworkName   string                    `yaml:"network_name"`
	LokiPushPort  int                       `yaml:"loki_push_port"`
	LokiPushPath  string                    `yaml:"loki_push_path"`
	PKIRootCAPath string                    `yaml:"pki_root_ca_path"`
	Registry      HostLogRendezvousRegistry `yaml:"registry"`
}

// VaultTopology represents the Bastion Vault and operator proxy network endpoints declared in workstation-topology.yaml.
type VaultTopology struct {
	BastionVault        BastionVault        `yaml:"vault_bastion"`
	OperatorVaultProxy  OperatorVaultProxy  `yaml:"operator_vault_proxy"`
	HostTelemetryScrape HostTelemetryScrape `yaml:"host_telemetry_scrape"`
	HostLogRendezvous   HostLogRendezvous   `yaml:"host_log_rendezvous"`
}

// ResolveProxyEndpoint resolves the proxy connection parameters of the single identity with access role.
func (v VaultTopology) ResolveProxyEndpoint(home string, role AccessRole) (ProxyEndpoint, error) {
	var names []string
	for name := range v.OperatorVaultProxy.Identities {
		if v.OperatorVaultProxy.ResolveIdentityRole(name).AccessTier == string(role) {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		slices.Sort(names)
		return ProxyEndpoint{}, fmt.Errorf("topology: operator_vault_proxy requires exactly one identity with access_tier %s, found %v", role, names)
	}
	name := names[0]
	base := filepath.Join(home, v.OperatorVaultProxy.UserConfigDir)
	return ProxyEndpoint{
		Identity:   name,
		Address:    "https://" + net.JoinHostPort(v.BastionVault.LoopbackIP, strconv.Itoa(v.OperatorVaultProxy.Identities[name].ListenPort)),
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
	if net.ParseIP(b.LoopbackIP) == nil || net.ParseIP(b.PublishIP) == nil {
		return VaultTopology{}, fmt.Errorf("topology: %s: vault_bastion requires valid IP addresses for loopback_ip and publish_ip", path)
	}
	if b.APIPort < 1 || b.APIPort > 65535 {
		return VaultTopology{}, fmt.Errorf("topology: %s: vault_bastion.api_port %d is outside 1 to 65535", path, b.APIPort)
	}
	return v, nil
}
