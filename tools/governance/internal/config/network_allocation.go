package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
)

// ErrInvalidNetworkAllocation reports a network allocation payload which violates the Bastion preconditions.
var ErrInvalidNetworkAllocation = errors.New("config: invalid network allocation")

var (
	dnsNamePattern     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	dnsLabelPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
	macPrefixPattern   = regexp.MustCompile(`^([0-9a-f]{2}:){2}[0-9a-f]{2}$`)
	hostSegmentIndexes = []int{249, 250}
)

// NetworkBaseline mirrors the network_baseline JSON schema validated by foundation-vault-bastion.
type NetworkBaseline struct {
	HostVIPOffset    int    `json:"host_vip_offset"`
	GlobalMACPrefix  string `json:"global_mac_prefix"`
	GlobalMTU        int    `json:"global_mtu"`
	GlobalMSS        int    `json:"global_mss"`
	NodeExporterPort int    `json:"node_exporter_port"`
	CIDRSubnetBits   int    `json:"cidr_subnet_bits"`
	CIDRNATOffset    int    `json:"cidr_nat_offset"`
	CIDRIndexMax     int    `json:"cidr_index_max"`
}

// NetworkAllocation represents the decoded deployment allocation fields stored in Bastion Vault.
type NetworkAllocation struct {
	DomainSuffix       string
	Stages             []string
	NetworkCIDR        string
	BastionPublishCIDR string
	PodNetworkCIDR     string
	ServiceNetworkCIDR string
	NetworkBaseline    NetworkBaseline
}

// ValidateNetworkAllocation verifies a flat KV v2 network allocation map against the Bastion preconditions.
func ValidateNetworkAllocation(raw map[string]string, publishIP string) error {
	if err := validateDomainAndStages(raw); err != nil {
		return err
	}
	baseline, err := decodeNetworkBaseline(raw["network_baseline"])
	if err != nil {
		return err
	}
	if err := validateNetworkBaseline(baseline); err != nil {
		return err
	}
	return validateNetworkCIDRs(raw, publishIP, baseline.CIDRSubnetBits)
}

// LoadAndValidateNetworkAllocation reads path as a flat string map and validates the decoded fields against publishIP.
func LoadAndValidateNetworkAllocation(path, publishIP string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %w", ErrInvalidNetworkAllocation, path, err)
	}
	if err := ValidateNetworkAllocation(raw, publishIP); err != nil {
		return nil, err
	}
	return raw, nil
}

func validateDomainAndStages(raw map[string]string) error {
	if !dnsNamePattern.MatchString(raw["domain_suffix"]) {
		return fmt.Errorf("%w: domain_suffix must be a lowercase DNS name", ErrInvalidNetworkAllocation)
	}
	var stages []string
	if err := json.Unmarshal([]byte(raw["stages"]), &stages); err != nil {
		return fmt.Errorf("%w: stages must be a JSON string array: %w", ErrInvalidNetworkAllocation, err)
	}
	if len(stages) == 0 {
		return fmt.Errorf("%w: stages must contain at least one label", ErrInvalidNetworkAllocation)
	}
	for _, stage := range stages {
		if !dnsLabelPattern.MatchString(stage) {
			return fmt.Errorf("%w: stages entry %q must be a lowercase DNS label", ErrInvalidNetworkAllocation, stage)
		}
	}
	return nil
}

func decodeNetworkBaseline(rawJSON string) (NetworkBaseline, error) {
	var baseline NetworkBaseline
	if err := json.Unmarshal([]byte(rawJSON), &baseline); err != nil {
		return NetworkBaseline{}, fmt.Errorf("%w: network_baseline must be valid JSON: %w", ErrInvalidNetworkAllocation, err)
	}
	return baseline, nil
}

func validateNetworkBaseline(b NetworkBaseline) error {
	switch {
	case b.HostVIPOffset <= 0 || b.HostVIPOffset >= 255:
		return fmt.Errorf("%w: host_vip_offset must stay inside 1 to 254", ErrInvalidNetworkAllocation)
	case !macPrefixPattern.MatchString(b.GlobalMACPrefix):
		return fmt.Errorf("%w: global_mac_prefix must match xx:xx:xx lowercase hex", ErrInvalidNetworkAllocation)
	case b.GlobalMSS <= 0 || b.GlobalMSS >= b.GlobalMTU:
		return fmt.Errorf("%w: global_mss must stay positive and less than global_mtu", ErrInvalidNetworkAllocation)
	case b.NodeExporterPort <= 0 || b.NodeExporterPort >= 65536:
		return fmt.Errorf("%w: node_exporter_port must stay inside 1 to 65535", ErrInvalidNetworkAllocation)
	case b.CIDRSubnetBits <= 0 || b.CIDRSubnetBits > 16:
		return fmt.Errorf("%w: cidr_subnet_bits must stay inside 1 to 16", ErrInvalidNetworkAllocation)
	case b.CIDRNATOffset < 1:
		return fmt.Errorf("%w: cidr_nat_offset must be at least 1", ErrInvalidNetworkAllocation)
	case b.CIDRIndexMax <= b.CIDRNATOffset || b.CIDRIndexMax > 2*b.CIDRNATOffset:
		return fmt.Errorf("%w: cidr_index_max must satisfy cidr_nat_offset < cidr_index_max <= 2*cidr_nat_offset", ErrInvalidNetworkAllocation)
	}
	limit := 1 << b.CIDRSubnetBits
	for _, index := range hostSegmentIndexes {
		if index <= b.CIDRIndexMax || index >= limit {
			return fmt.Errorf("%w: host segment index %d must exceed cidr_index_max and fit within cidr_subnet_bits", ErrInvalidNetworkAllocation, index)
		}
	}
	return nil
}

func validateNetworkCIDRs(raw map[string]string, publishIP string, subnetBits int) error {
	networkCIDR, err := parseCanonicalIPv4Prefix("network_cidr", raw["network_cidr"])
	if err != nil {
		return err
	}
	if networkCIDR.Bits() != 16 {
		return fmt.Errorf("%w: network_cidr must use prefix /16", ErrInvalidNetworkAllocation)
	}

	bastionPublish, err := parseCanonicalIPv4Prefix("bastion_publish_cidr", raw["bastion_publish_cidr"])
	if err != nil {
		return err
	}
	if bastionPublish.Bits() != networkCIDR.Bits()+subnetBits || bastionPublish.Addr() != networkCIDR.Addr() {
		return fmt.Errorf("%w: bastion_publish_cidr must equal segment 0 of network_cidr", ErrInvalidNetworkAllocation)
	}

	pubAddr, err := netip.ParseAddr(publishIP)
	if err != nil || !pubAddr.Is4() || !bastionPublish.Contains(pubAddr) {
		return fmt.Errorf("%w: publish_ip %q lies outside bastion_publish_cidr %s", ErrInvalidNetworkAllocation, publishIP, bastionPublish)
	}

	podCIDR, err := parseCanonicalIPv4Prefix("pod_network_cidr", raw["pod_network_cidr"])
	if err != nil {
		return err
	}
	if podCIDR.Bits()+subnetBits > 32 {
		return fmt.Errorf("%w: pod_network_cidr prefix plus cidr_subnet_bits must not exceed 32", ErrInvalidNetworkAllocation)
	}

	serviceCIDR, err := parseCanonicalIPv4Prefix("service_network_cidr", raw["service_network_cidr"])
	if err != nil {
		return err
	}
	if serviceCIDR.Bits()+subnetBits > 32 {
		return fmt.Errorf("%w: service_network_cidr prefix plus cidr_subnet_bits must not exceed 32", ErrInvalidNetworkAllocation)
	}

	if networkCIDR.Overlaps(podCIDR) || networkCIDR.Overlaps(serviceCIDR) || podCIDR.Overlaps(serviceCIDR) {
		return fmt.Errorf("%w: network_cidr, pod_network_cidr, and service_network_cidr must not overlap", ErrInvalidNetworkAllocation)
	}
	return nil
}

func parseCanonicalIPv4Prefix(field, rawValue string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(rawValue)
	if err != nil || !prefix.Addr().Is4() || prefix != prefix.Masked() {
		return netip.Prefix{}, fmt.Errorf("%w: %s must be a canonical IPv4 CIDR", ErrInvalidNetworkAllocation, field)
	}
	return prefix, nil
}
