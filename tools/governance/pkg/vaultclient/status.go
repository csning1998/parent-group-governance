package vaultclient

import (
	"context"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// probeTimeout bounds interactive status probes.
// The Vault API defaults of 60 seconds and two retries stall the CLI banner against an unreachable address.
const probeTimeout = 3 * time.Second

// SealStatus records reachability, initialization, and seal state for a target Vault instance.
type SealStatus struct {
	Reachable   bool
	Initialized bool
	Sealed      bool
}

// InspectStatus queries cfg and returns the reachability, initialization, and seal status of Vault.
func InspectStatus(ctx context.Context, cfg Config) SealStatus {
	client, err := NewClient(cfg)
	if err != nil {
		return SealStatus{}
	}
	st, err := probeSealStatus(ctx, client)
	if err != nil {
		return SealStatus{}
	}
	return SealStatus{
		Reachable:   true,
		Initialized: st.Initialized,
		Sealed:      st.Sealed,
	}
}

// ProbeSealState queries seal status through client and returns running and sealed flags.
func ProbeSealState(ctx context.Context, client *vaultapi.Client) (running, sealed bool, err error) {
	if client == nil {
		return false, false, fmt.Errorf("vaultclient: nil client provided")
	}
	st, err := probeSealStatus(ctx, client)
	if err != nil {
		return false, false, nil
	}
	return true, st.Sealed, nil
}

// probeSealStatus clones client with zero retries and probeTimeout to bound interactive status checks.
func probeSealStatus(ctx context.Context, client *vaultapi.Client) (*vaultapi.SealStatusResponse, error) {
	if client == nil {
		return nil, fmt.Errorf("vaultclient: nil client provided")
	}
	probe, err := client.Clone()
	if err != nil {
		return nil, fmt.Errorf("vaultclient: clone client for probe: %w", err)
	}
	probe.SetMaxRetries(0)
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	return probe.Sys().SealStatusWithContext(ctx)
}
