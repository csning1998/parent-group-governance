package ansible

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type composeShipperDoc struct {
	Services map[string]struct {
		Image       string   `yaml:"image"`
		Container   string   `yaml:"container_name"`
		Profiles    []string `yaml:"profiles"`
		Volumes     []string `yaml:"volumes"`
		NetworkMode string   `yaml:"network_mode"`
		UsernsMode  string   `yaml:"userns_mode"`
	} `yaml:"services"`
}

type topologyLogRendezvousDoc struct {
	HostLogRendezvous struct {
		NetworkName   string `yaml:"network_name"`
		LokiPushPort  int    `yaml:"loki_push_port"`
		LokiPushPath  string `yaml:"loki_push_path"`
		PKIRootCAPath string `yaml:"pki_root_ca_path"`
		Registry      struct {
			Mount            string `yaml:"vault_kv_mount"`
			Path             string `yaml:"vault_kv_path"`
			CIDRField        string `yaml:"cidr_field"`
			IPField          string `yaml:"ip_field"`
			ServerNamesField string `yaml:"server_names_field"`
		} `yaml:"registry"`
	} `yaml:"host_log_rendezvous"`
}

// TestVaultServerLogFileAndAlloyComposeContract verifies Vault server log rotation, Alloy shipper compose isolation, and rendezvous topology wiring.
func TestVaultServerLogFileAndAlloyComposeContract(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	repoRoot := filepath.Dir(ansibleDir)

	vaultHCLBytes, err := os.ReadFile(filepath.Join(ansibleDir, "roles", "workstation_libvirt", "templates", "vault.hcl.j2"))
	if err != nil {
		t.Fatalf("read vault.hcl.j2: %v", err)
	}
	vaultHCL := string(vaultHCLBytes)
	for _, want := range []string{
		`log_file`,
		`"/opt/vault/logs/vault.log"`,
		`log_rotate_duration`,
		`"24h"`,
		`log_rotate_max_files = 14`,
	} {
		if !strings.Contains(vaultHCL, want) {
			t.Errorf("vault.hcl.j2 missing %q", want)
		}
	}

	compose := mustReadYAML[composeShipperDoc](t, filepath.Join(repoRoot, "compose.yml"))
	vaultSvc, ok := compose.Services["vault-server"]
	if !ok {
		t.Fatalf("compose.yml missing vault-server service")
	}
	if !slices.Contains(vaultSvc.Volumes, "./vault/logs:/opt/vault/logs") {
		t.Errorf("compose.yml vault-server volumes = %v, want ./vault/logs:/opt/vault/logs", vaultSvc.Volumes)
	}

	shipper, ok := compose.Services["vault-log-shipper"]
	if !ok {
		t.Fatalf("compose.yml missing vault-log-shipper service")
	}
	if shipper.Image != "docker.io/grafana/alloy:v1.10.0" {
		t.Errorf("vault-log-shipper image = %q, want docker.io/grafana/alloy:v1.10.0", shipper.Image)
	}
	if !slices.Equal(shipper.Profiles, []string{"host-log-shipper"}) {
		t.Errorf("vault-log-shipper profiles = %v, want [host-log-shipper]", shipper.Profiles)
	}
	if shipper.NetworkMode != "host" || shipper.UsernsMode != "keep-id" {
		t.Errorf("vault-log-shipper network_mode=%q userns_mode=%q, want host and keep-id", shipper.NetworkMode, shipper.UsernsMode)
	}
	for _, wantVol := range []string{
		"./vault/logs:/opt/vault/logs:ro",
		"./vault/alloy/config.alloy:/etc/alloy/config.alloy:ro",
		"./vault/alloy/pki-root-ca.pem:/etc/alloy/pki-root-ca.pem:ro",
		"./vault/alloy/data:/var/lib/alloy/data",
	} {
		if !slices.Contains(shipper.Volumes, wantVol) {
			t.Errorf("vault-log-shipper volumes = %v, missing %q", shipper.Volumes, wantVol)
		}
	}
	for _, vol := range shipper.Volumes {
		if strings.HasSuffix(vol, ":z") || strings.HasSuffix(vol, ":Z") {
			t.Errorf("vault-log-shipper volume %q must not declare :z or :Z", vol)
		}
		if strings.Contains(vol, "./vault/audit") || strings.Contains(vol, "./vault/tls") {
			t.Errorf("vault-log-shipper volume %q must not mount vault/audit or vault/tls", vol)
		}
	}

	topo := mustReadYAML[topologyLogRendezvousDoc](t, filepath.Join(repoRoot, "workstation-topology.yaml"))
	if topo.HostLogRendezvous.NetworkName != "host-log-rendezvous" ||
		topo.HostLogRendezvous.LokiPushPort == 0 ||
		topo.HostLogRendezvous.LokiPushPath == "" ||
		topo.HostLogRendezvous.PKIRootCAPath == "" ||
		topo.HostLogRendezvous.Registry.CIDRField == "" ||
		topo.HostLogRendezvous.Registry.IPField == "" ||
		topo.HostLogRendezvous.Registry.ServerNamesField == "" {
		t.Errorf("workstation-topology.yaml host_log_rendezvous incomplete: %+v", topo.HostLogRendezvous)
	}

	alloyTplBytes, err := os.ReadFile(filepath.Join(ansibleDir, "roles", "workstation_host_telemetry", "templates", "alloy-config.alloy.j2"))
	if err != nil {
		t.Fatalf("read alloy-config.alloy.j2: %v", err)
	}
	alloyTpl := string(alloyTplBytes)
	for _, want := range []string{`ca_file     = "/etc/alloy/pki-root-ca.pem"`, `server_name`} {
		if !strings.Contains(alloyTpl, want) {
			t.Errorf("alloy-config.alloy.j2 missing %q", want)
		}
	}
}
