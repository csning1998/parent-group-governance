package ansible

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type topologyTextfileDoc struct {
	HostTelemetryScrape struct {
		TextfileCollectorDir string `yaml:"textfile_collector_dir"`
	} `yaml:"host_telemetry_scrape"`
}

// TestWorkstationVaultAuditTextfileContract verifies textfile collector wiring across topology, role contract, and config template.
func TestWorkstationVaultAuditTextfileContract(t *testing.T) {
	ansibleDir := mustResolveAnsibleDir(t)
	topoPath := filepath.Join(filepath.Dir(ansibleDir), "workstation-topology.yaml")
	topo := mustReadYAML[topologyTextfileDoc](t, topoPath)
	if !filepath.IsAbs(topo.HostTelemetryScrape.TextfileCollectorDir) {
		t.Fatalf("workstation-topology.yaml host_telemetry_scrape.textfile_collector_dir = %q, want non-empty absolute path", topo.HostTelemetryScrape.TextfileCollectorDir)
	}

	roleDir := filepath.Join(ansibleDir, "roles", "workstation_vault_audit")
	spec := mustReadYAML[argumentSpecsDoc](t, filepath.Join(roleDir, "meta", "argument_specs.yml"))
	mainEntry, ok := spec.ArgumentSpecs["main"]
	if !ok {
		t.Fatalf("workstation_vault_audit argument_specs.yml missing main entry")
	}
	if _, exists := mainEntry.Options["workstation_vault_audit_host_telemetry_scrape"]; !exists {
		t.Errorf("workstation_vault_audit argument_specs.yml missing option workstation_vault_audit_host_telemetry_scrape")
	}

	tplBytes, err := os.ReadFile(filepath.Join(roleDir, "templates", "config.json.j2"))
	if err != nil {
		t.Fatalf("read config.json.j2: %v", err)
	}
	if !strings.Contains(string(tplBytes), `"textfile_dir"`) {
		t.Errorf("workstation_vault_audit/templates/config.json.j2 missing key \"textfile_dir\"")
	}
}
