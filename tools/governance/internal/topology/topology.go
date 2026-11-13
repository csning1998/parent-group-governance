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
	// AccessRoleAdministrator identifies the operator proxy carrying administrator privileges.
	AccessRoleAdministrator AccessRole = "administrator"
	// AccessRoleCredentialRotator identifies the operator proxy carrying credential rotation privileges.
	AccessRoleCredentialRotator AccessRole = "credential-rotator"
)

const (
	accessTierCredentialDistributor = "credential-distributor"
	accessTierConsumer              = "consumer"
	accessTierTenant                = "tenant"
)

// BastionVault is the listener topology of the Bastion Vault server.
type BastionVault struct {
	LoopbackAddress string `yaml:"loopback_address"` // host loopback address (127.0.0.1) for local processes
	PublishAddress  string `yaml:"publish_address"`  // hypervisor bridge address (172.16.0.1) for guest VM / runner access
	APIPort         int    `yaml:"api_port"`         // primary HTTPS API port bound by Vault daemon (8200)
	ClusterPort     int    `yaml:"cluster_port"`     // Raft cluster request forwarding and HA interconnect port (8201)
	MetricsPort     int    `yaml:"metrics_port"`     // unauthenticated Prometheus metrics telemetry scraping port (8202)
}

// APIEndpoint returns the loopback API listener URL (e.g. https://127.0.0.1:8200) used by CLI operations.
func (b BastionVault) APIEndpoint() string {
	return "https://" + net.JoinHostPort(b.LoopbackAddress, strconv.Itoa(b.APIPort))
}

// ProxyIdentity defines one operator proxy instance listening on loopback and mapping to a Vault cert role.
type ProxyIdentity struct {
	ListenPort int `yaml:"listen_port"` // local TCP port on 127.0.0.1 bound by this proxy instance (e.g. 8210)

	CodeReviewerVariableProjects []string `yaml:"code_reviewer_variable_projects"` // project paths relative to the top-level group which receive the code reviewer CI/CD variables
}

// IdentityRole holds the access tier, owner code, and KV v2 state token path derived from an identity name.
type IdentityRole struct {
	AccessTier       string
	OwnerCode        string
	StateBackendPath string // omitted for credential-rotator because the rotator identity does not execute Terraform
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
	VaultKVMount string `yaml:"vault_kv_mount"` // KV v2 mount holding state backend tokens
	VaultKVField string `yaml:"vault_kv_field"` // secret key holding the GitLab state backend token
}

// OperatorVaultProxy holds client connection parameters and identity mappings for operator Vault proxies.
type OperatorVaultProxy struct {
	GovernanceOwnerCode string `yaml:"governance_owner_code"` // repository owner code assigned to the administrator and credential-rotator identities

	CertAuthMount    string                   `yaml:"cert_auth_mount"`   // Vault TLS certificate auth mount path matching CN operator-<identity>
	UserConfigDir    string                   `yaml:"user_config_dir"`   // directory relative to user $HOME storing mTLS client certs and systemd units
	PlaceholderToken string                   `yaml:"placeholder_token"` // dummy token string required by client headers and replaced by the proxy
	StateBackend     StateBackend             `yaml:"state_backend"`     // KV v2 location of the GitLab state token of each owner code
	Identities       map[string]ProxyIdentity `yaml:"identities"`        // operator role entries mapped to their local listener ports and tiers
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
		return KVField{}, fmt.Errorf("topology: operator_vault_proxy MUST declare the identity %s-%s, found %d", accessTierCredentialDistributor, ownerCode, len(paths))
	}
	backend := v.OperatorVaultProxy.StateBackend
	return KVField{Mount: backend.VaultKVMount, Path: paths[0], Field: backend.VaultKVField}, nil
}

// ProxyEndpoint holds the client connection parameters required to communicate with a local operator Vault Proxy.
type ProxyEndpoint struct {
	Identity   string // operator proxy identity name (e.g. governance, rotation, foundation)
	Address    string // loopback HTTPS URL of the local proxy listener (e.g. https://127.0.0.1:8210)
	CACert     string // absolute filesystem path to local root CA certificate bundle (ca.pem)
	ClientCert string // absolute filesystem path to operator mTLS client certificate (client.pem)
	ClientKey  string // absolute filesystem path to operator mTLS client private key (client-key.pem)
	Token      string // dummy placeholder token (proxy-supplied) replaced by the proxy via mTLS
}

// HostTelemetryRegistry specifies the Vault KV v2 coordinates at which foundation-vault-bastion publishes the scrape subnet.
type HostTelemetryRegistry struct {
	Mount        string `yaml:"vault_kv_mount"`
	Path         string `yaml:"vault_kv_path"`
	CIDRField    string `yaml:"cidr_field"`
	AddressField string `yaml:"address_field"`
}

// HostTelemetryScrape holds the Vault registry reference for the host telemetry scrape network.
type HostTelemetryScrape struct {
	Registry HostTelemetryRegistry `yaml:"registry"`
}

// VaultTopology represents the Bastion Vault and operator proxy network endpoints declared in workstation-topology.yaml.
type VaultTopology struct {
	BastionVault        BastionVault        `yaml:"vault_bastion"`         // Bastion Vault network listener bindings
	OperatorVaultProxy  OperatorVaultProxy  `yaml:"operator_vault_proxy"`  // local operator mTLS proxies configuration
	HostTelemetryScrape HostTelemetryScrape `yaml:"host_telemetry_scrape"` // observability scrape network configuration
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
		return VaultTopology{}, fmt.Errorf("topology: %s: vault_bastion MUST declare loopback_address and publish_address as IP addresses", path)
	}
	if b.APIPort < 1 || b.APIPort > 65535 {
		return VaultTopology{}, fmt.Errorf("topology: %s: vault_bastion.api_port %d is outside 1 to 65535", path, b.APIPort)
	}
	return v, nil
}
