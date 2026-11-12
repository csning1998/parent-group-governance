package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/config"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/topology"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/vaultops"
)

const labelHostTelemetry = "[Host] Apply Host Telemetry Scrape Network"

// newHostTelemetryApp wires the issued tokens fixture to the registry location of the host telemetry segment.
func newHostTelemetryApp(t *testing.T) (*app, *issuedVault) {
	t.Helper()
	a, vault, _ := newIssuedTokensApp(t, nil)
	a.topology.HostTelemetryScrape = topology.HostTelemetryScrape{Registry: topology.HostTelemetryRegistry{
		Mount:        "registry",
		Path:         "platform/network/allocation",
		CIDRField:    "host_telemetry_scrape_cidr",
		AddressField: "host_telemetry_scrape_address",
	}}
	return a, vault
}

// TestBuildHostTelemetryPlaybook_InjectsTheSegmentAndCoversTheAddress asserts the injected segment, the libvirt
// inputs which the terminator frontend of the address needs, and the publish certificate which names the address.
func TestBuildHostTelemetryPlaybook_InjectsTheSegmentAndCoversTheAddress(t *testing.T) {
	a, vault := newHostTelemetryApp(t)
	vault.secrets["registry/platform/network/allocation"] = map[string]any{
		"host_telemetry_scrape_cidr":    "192.0.2.0/24",
		"host_telemetry_scrape_address": "192.0.2.1",
	}
	tlsDir := a.newVaultPaths().TLSDir()
	err := vaultops.GenerateTLS(tlsDir, vaultops.Listeners{Loopback: net.ParseIP("127.0.0.1"), Publish: net.ParseIP("192.0.2.10")})
	if err != nil {
		t.Fatalf("GenerateTLS: %v", err)
	}
	facts, err := config.DetectHostFacts()
	if err != nil {
		t.Fatalf("DetectHostFacts: %v", err)
	}

	pb, err := a.buildHostTelemetryPlaybook(context.Background())
	want := map[string]any{
		"workstation_host_telemetry_scrape_cidr":    "192.0.2.0/24",
		"workstation_host_telemetry_scrape_address": "192.0.2.1",
		"workstation_libvirt_operator_user":         facts.CurrentUname,
		"workstation_libvirt_vault_config_path":     filepath.Join(a.root, "vault", "vault.hcl"),
	}
	if err != nil || pb.file != "playbooks/workstation_host_telemetry.yaml" || !maps.Equal(pb.extraVars, want) {
		t.Errorf("buildHostTelemetryPlaybook = %+v, %v, want the telemetry playbook with %v", pb, err, want)
	}
	cert := readPublishCert(t, tlsDir)
	if !slices.ContainsFunc(cert.IPAddresses, net.ParseIP("192.0.2.1").Equal) {
		t.Errorf("publish SAN = %v, want the host telemetry scrape address", cert.IPAddresses)
	}
}

func readPublishCert(t *testing.T, tlsDir string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(tlsDir, "publish.pem"))
	if err != nil {
		t.Fatalf("read publish.pem: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("publish.pem holds no PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse publish.pem: %v", err)
	}
	return cert
}

func TestBuildHostTelemetryPlaybook_ReportsAnUnpublishedSegment(t *testing.T) {
	a, _ := newHostTelemetryApp(t)

	_, err := a.buildHostTelemetryPlaybook(context.Background())
	if err == nil || !strings.Contains(err.Error(), "registry/platform/network/allocation") {
		t.Errorf("buildHostTelemetryPlaybook error = %v, want the unread registry path", err)
	}
}

func TestHostTelemetryIsAMenuOptionAndAHostCommand(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	if labels := menuLabels(a.buildMenuOptions()); !slices.Contains(labels, labelHostTelemetry) {
		t.Errorf("menu labels = %q, want %q", labels, labelHostTelemetry)
	}
	cmd, _, err := a.newHostCmd().Find([]string{"apply-host-telemetry"})
	if err != nil || cmd.Name() != "apply-host-telemetry" {
		t.Errorf("host command = %v, %v, want apply-host-telemetry", cmd, err)
	}
}
