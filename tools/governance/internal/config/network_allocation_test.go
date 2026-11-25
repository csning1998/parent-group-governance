package config

import (
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	lookupKeyPattern   = regexp.MustCompile(`lookup\(local\.network_allocation_raw,\s*"([a-z0-9_]+)"`)
	baselineKeyPattern = regexp.MustCompile(`local\.network_baseline_raw\.([a-z0-9_]+)`)
)

func TestNetworkAllocationExampleMatchesTerraformContract(t *testing.T) {
	layerDir := filepath.Join("..", "..", "..", "..", "terraform", "layers", "foundation-vault-bastion")

	exampleBytes, err := os.ReadFile(filepath.Join(layerDir, "network-allocation.example.json"))
	if err != nil {
		t.Fatalf("read example JSON: %v", err)
	}
	tfBytes, err := os.ReadFile(filepath.Join(layerDir, "network-allocation.tf"))
	if err != nil {
		t.Fatalf("read Terraform allocation contract: %v", err)
	}

	var exampleRaw map[string]string
	if err := json.Unmarshal(exampleBytes, &exampleRaw); err != nil {
		t.Fatalf("decode example JSON as flat string map: %v", err)
	}

	tfText := string(tfBytes)
	assertSortedSetEqual(t, "outer allocation keys", extractMapKeys(exampleRaw), extractRegexKeys(tfText, lookupKeyPattern))

	baselineJSON, ok := exampleRaw["network_baseline"]
	if !ok {
		t.Fatal("example JSON omits network_baseline")
	}
	var baselineRaw map[string]any
	if err := json.Unmarshal([]byte(baselineJSON), &baselineRaw); err != nil {
		t.Fatalf("decode example network_baseline JSON: %v", err)
	}
	assertSortedSetEqual(t, "network_baseline keys", extractMapKeys(baselineRaw), extractRegexKeys(tfText, baselineKeyPattern))
}

func TestValidateNetworkAllocationAcceptsValidPayload(t *testing.T) {
	payload := buildValidNetworkAllocation()
	if err := ValidateNetworkAllocation(payload, "10.99.0.1"); err != nil {
		t.Fatalf("ValidateNetworkAllocation returned unexpected error: %v", err)
	}
}

func TestValidateNetworkAllocationRejectsInvalidPayload(t *testing.T) {
	cases := []struct {
		name      string
		publishIP string
		mutate    func(map[string]string)
		wantPart  string
	}{
		{
			name:      "missing domain_suffix",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { delete(m, "domain_suffix") },
			wantPart:  "domain_suffix",
		},
		{
			name:      "single-label domain_suffix",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["domain_suffix"] = "foobar" },
			wantPart:  "domain_suffix",
		},
		{
			name:      "empty stages",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["stages"] = "[]" },
			wantPart:  "stages",
		},
		{
			name:      "malformed stages JSON",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["stages"] = "not-json" },
			wantPart:  "stages",
		},
		{
			name:      "invalid stage DNS label",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["stages"] = `["foo_bar"]` },
			wantPart:  "stages",
		},
		{
			name:      "non-canonical network_cidr",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["network_cidr"] = "10.99.0.1/16" },
			wantPart:  "network_cidr",
		},
		{
			name:      "network_cidr not /16",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["network_cidr"] = "10.99.0.0/20" },
			wantPart:  "network_cidr",
		},
		{
			name:      "invalid bastion_publish_cidr",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["bastion_publish_cidr"] = "not-a-cidr" },
			wantPart:  "bastion_publish_cidr",
		},
		{
			name:      "bastion_publish_cidr not segment 0",
			publishIP: "10.99.1.1",
			mutate:    func(m map[string]string) { m["bastion_publish_cidr"] = "10.99.1.0/24" },
			wantPart:  "bastion_publish_cidr",
		},
		{
			name:      "publish_ip outside bastion_publish_cidr",
			publishIP: "10.99.5.1",
			mutate:    func(map[string]string) {},
			wantPart:  "publish_ip",
		},
		{
			name:      "overlapping pod and service CIDRs",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["pod_network_cidr"] = "10.192.0.0/10"
				m["service_network_cidr"] = "10.192.0.0/12"
			},
			wantPart: "overlap",
		},
		{
			name:      "invalid pod_network_cidr",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["pod_network_cidr"] = "not-a-cidr" },
			wantPart:  "pod_network_cidr",
		},
		{
			name:      "pod_network_cidr prefix plus cidr_subnet_bits exceeds 32",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["pod_network_cidr"] = "10.192.0.0/25" },
			wantPart:  "pod_network_cidr",
		},
		{
			name:      "invalid service_network_cidr",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["service_network_cidr"] = "not-a-cidr" },
			wantPart:  "service_network_cidr",
		},
		{
			name:      "service_network_cidr prefix plus cidr_subnet_bits exceeds 32",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["service_network_cidr"] = "100.64.0.0/25" },
			wantPart:  "service_network_cidr",
		},
		{
			name:      "malformed network_baseline JSON",
			publishIP: "10.99.0.1",
			mutate:    func(m map[string]string) { m["network_baseline"] = "{foo-bar" },
			wantPart:  "network_baseline",
		},
		{
			name:      "host_vip_offset out of bounds",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":0,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":248}`
			},
			wantPart: "host_vip_offset",
		},
		{
			name:      "global_mss not less than global_mtu",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1450,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":248}`
			},
			wantPart: "global_mss",
		},
		{
			name:      "node_exporter_port out of bounds",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":0,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":248}`
			},
			wantPart: "node_exporter_port",
		},
		{
			name:      "cidr_subnet_bits out of bounds",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":17,"cidr_nat_offset":124,"cidr_index_max":248}`
			},
			wantPart: "cidr_subnet_bits",
		},
		{
			name:      "cidr_nat_offset below 1",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":0,"cidr_index_max":248}`
			},
			wantPart: "cidr_nat_offset",
		},
		{
			name:      "cidr_index_max not above cidr_nat_offset",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":124}`
			},
			wantPart: "cidr_index_max",
		},
		{
			name:      "host segment index not above cidr_index_max",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54:ff","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":125,"cidr_index_max":249}`
			},
			wantPart: "cidr_index_max",
		},
		{
			name:      "invalid global_mac_prefix",
			publishIP: "10.99.0.1",
			mutate: func(m map[string]string) {
				m["network_baseline"] = `{"host_vip_offset":240,"global_mac_prefix":"52:54","global_mtu":1450,"global_mss":1360,"node_exporter_port":19100,"cidr_subnet_bits":8,"cidr_nat_offset":124,"cidr_index_max":248}`
			},
			wantPart: "global_mac_prefix",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := buildValidNetworkAllocation()
			tc.mutate(payload)

			err := ValidateNetworkAllocation(payload, tc.publishIP)
			if !errors.Is(err, ErrInvalidNetworkAllocation) {
				t.Fatalf("ValidateNetworkAllocation error = %v, want errors.Is(_, ErrInvalidNetworkAllocation)", err)
			}
			if !strings.Contains(err.Error(), tc.wantPart) {
				t.Errorf("error = %q, want substring %q", err.Error(), tc.wantPart)
			}
		})
	}
}

func TestLoadAndValidateNetworkAllocationAcceptsValidFile(t *testing.T) {
	validPayload := buildValidNetworkAllocation()
	validJSON, err := json.Marshal(validPayload)
	if err != nil {
		t.Fatalf("marshal valid allocation: %v", err)
	}

	path := writeTestJSONFile(t, "network-allocation.json", validJSON)
	got, err := LoadAndValidateNetworkAllocation(path, "10.99.0.1")
	if err != nil {
		t.Fatalf("LoadAndValidateNetworkAllocation unexpected error: %v", err)
	}
	if !maps.Equal(got, validPayload) {
		t.Errorf("LoadAndValidateNetworkAllocation = %v, want %v", got, validPayload)
	}
}

func TestLoadAndValidateNetworkAllocationRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name:    "missing file",
			path:    filepath.Join(t.TempDir(), "missing.json"),
			wantErr: os.ErrNotExist,
		},
		{
			name:    "non-string JSON value",
			path:    writeTestJSONFile(t, "invalid-type.json", []byte(`{"domain_suffix": 123}`)),
			wantErr: ErrInvalidNetworkAllocation,
		},
		{
			name:    "valid JSON failing validation",
			path:    writeTestJSONFile(t, "invalid-domain.json", []byte(`{"domain_suffix": "foobar"}`)),
			wantErr: ErrInvalidNetworkAllocation,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadAndValidateNetworkAllocation(tc.path, "10.99.0.1")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("LoadAndValidateNetworkAllocation error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}
		})
	}
}

func writeTestJSONFile(t *testing.T, name string, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildValidNetworkAllocation() map[string]string {
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

func extractMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func extractRegexKeys(text string, re *regexp.Regexp) []string {
	seen := make(map[string]struct{})
	for _, match := range re.FindAllStringSubmatch(text, -1) {
		seen[match[1]] = struct{}{}
	}
	return extractMapKeys(seen)
}

func assertSortedSetEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s mismatch:\n got:  %v\n want: %v", label, got, want)
	}
}
