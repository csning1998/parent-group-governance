// Package secretrotate rotates Vault backed service credentials with advisory locking and WAL recovery.
// Refer to tools/governance/README.md Section 6 and Section 7 for the design.
package secretrotate

import (
	"context"
	"errors"
	"fmt"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretgen"
)

// ErrAuthRejected marks a DeployFunc failure attributed to previous itself.
var ErrAuthRejected = errors.New("secretrotate: the live service rejected the previous credential")

// ErrNoLiveCredential marks a live service accepting none of the candidate credentials.
var ErrNoLiveCredential = errors.New("secretrotate: the live service accepts none of the known credentials")

// DeployFunc deploys a rotated secret against the target service with previous as the authentication credential.
// Implementations wrap ErrAuthRejected when the service rejects previous.
type DeployFunc func(ctx context.Context, previous, next string) error

// Spec describes one rotatable secret.
type Spec struct {
	Mount string
	Path  string
	Field string

	Length  int
	Classes []secretgen.CharClass

	Deploy DeployFunc
	Verify VerifyFunc

	// FactoryDefaultPassword specifies the initial password of a freshly provisioned service.
	FactoryDefaultPassword string
}

// VerifyFunc reports whether the live service accepts secret without changing the service.
// Implementations return an error instead of false for an inconclusive answer.
type VerifyFunc func(ctx context.Context, secret string) (bool, error)

// deployRaceResolvedError reports a Deploy failure caused by a concurrent external write.
type deployRaceResolvedError struct {
	Resolved string
	cause    error
}

// rotationState is the write ahead record staged at "<field>_rotation" before calling Deploy.
type rotationState struct {
	Previous    string `json:"previous"`
	PendingNext string `json:"pending_next"`
}

// vaultField holds the secret value and presence flag read under the rotation lock.
type vaultField struct {
	value  string
	exists bool
}

type rotator struct {
	store fieldStore
	spec  Spec
	log   func(string)
}

func newRotator(client *vaultapi.Client, spec Spec, log func(string)) rotator {
	return rotator{
		store: newFieldStore(client, spec.Mount, spec.Path, spec.Field),
		spec:  spec,
		log:   log,
	}
}

func (r rotator) logf(msg string) {
	if r.log != nil {
		r.log(msg)
	}
}

// Exists reports whether Vault stores a value for spec.
func Exists(ctx context.Context, client *vaultapi.Client, spec Spec) bool {
	_, ok := newFieldStore(client, spec.Mount, spec.Path, spec.Field).readField(ctx)
	return ok
}

// Reconcile deploys the Vault value of spec to a drifted live service without generating or writing to Vault.
// Non-empty operatorSupplied overrides all other authentication candidates.
func Reconcile(ctx context.Context, client *vaultapi.Client, spec Spec, operatorSupplied string) error {
	if err := requireVerify(spec); err != nil {
		return err
	}
	r := newRotator(client, spec, nil)
	next, ok := r.store.readField(ctx)
	if !ok {
		return fmt.Errorf("secretrotate: no value in Vault at %s/%s#%s to reconcile", spec.Mount, spec.Path, spec.Field)
	}

	inSync, err := spec.Verify(ctx, next)
	if err != nil {
		return fmt.Errorf("secretrotate: verify the Vault value: %w", err)
	}
	if inSync {
		return nil
	}

	var candidates []string
	if operatorSupplied != "" {
		candidates = []string{operatorSupplied}
	} else {
		if st, staged := r.store.readRotationState(ctx); staged {
			candidates = append(candidates, st.PendingNext)
		}
		if spec.FactoryDefaultPassword != "" {
			candidates = append(candidates, spec.FactoryDefaultPassword)
		}
	}
	live, err := r.resolveLiveCredential(ctx, candidates)
	if err != nil {
		return err
	}
	return spec.Deploy(ctx, live, next)
}

// Rotate verifies the live credential, generates a replacement, deploys it, and commits it to Vault.
func Rotate(ctx context.Context, client *vaultapi.Client, spec Spec, log func(string)) (string, error) {
	if err := requireVerify(spec); err != nil {
		return "", err
	}
	r := newRotator(client, spec, log)
	if _, docExists := r.store.readDocument(ctx); !docExists && r.store.isDestroyedOutOfBand(ctx) {
		return "", fmt.Errorf("secretrotate: %s/%s contained data before and now reads back empty, refusing to mint a value the live service was never given", spec.Mount, spec.Path)
	}

	holder, err := r.store.acquireLock(ctx)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := r.store.releaseLock(ctx, holder); err != nil {
			r.logf("Warning: failed to release the rotation lock, the lock will expire at its own TTL: " + err.Error())
		}
	}()

	previous, exists := r.store.readField(ctx)
	if recovered, ok, err := r.recoverPending(ctx); err != nil || ok {
		return recovered, err
	}

	// Rebuilt services accept the factory default while a rebuilt Vault has no stored value.
	var candidates []string
	if exists {
		candidates = append(candidates, previous)
	}
	if spec.FactoryDefaultPassword != "" {
		candidates = append(candidates, spec.FactoryDefaultPassword)
	}
	live, err := r.resolveLiveCredential(ctx, candidates)
	if err != nil {
		return "", err
	}

	next, err := secretgen.Generate(spec.Length, spec.Classes...)
	if err != nil {
		return "", err
	}
	return r.commit(ctx, vaultField{value: previous, exists: exists}, live, next)
}

func (e *deployRaceResolvedError) Error() string {
	return fmt.Sprintf("secretrotate: deploy failed against a stale previous, a concurrent write already resolved this credential: %v", e.cause)
}

func (e *deployRaceResolvedError) Unwrap() error { return e.cause }

func (r rotator) commit(ctx context.Context, read vaultField, live, next string) (string, error) {
	if err := r.stageAndDeploy(ctx, read, live, next); err != nil {
		var raced *deployRaceResolvedError
		if errors.As(err, &raced) {
			return r.resolveDeployedElsewhere(ctx, raced)
		}
		return "", err
	}

	if err := r.store.writeField(ctx, next); err != nil {
		return "", fmt.Errorf("secretrotate: rotated but the Vault write failed, re-run to recover the staged value: %w", err)
	}
	if err := r.store.clearRotationState(ctx); err != nil {
		return "", fmt.Errorf("secretrotate: rotated and committed but clearing the staged rotation state failed: %w", err)
	}
	r.logf("New value stored at " + r.spec.Mount + "/" + r.spec.Path + "#" + r.spec.Field + ".")
	return next, nil
}

// recoverPending verifies a staged pending value from an interrupted run and falls through only when rejected.
func (r rotator) recoverPending(ctx context.Context) (string, bool, error) {
	st, ok := r.store.readRotationState(ctx)
	if !ok {
		return "", false, nil
	}
	live, err := r.spec.Verify(ctx, st.PendingNext)
	if err != nil {
		return "", false, fmt.Errorf("secretrotate: verify the staged pending value: %w", err)
	}
	if !live {
		return "", false, nil
	}
	if err := r.store.writeField(ctx, st.PendingNext); err != nil {
		return "", false, fmt.Errorf("secretrotate: recovered pending value but the Vault commit failed: %w", err)
	}
	if err := r.store.clearRotationState(ctx); err != nil {
		return "", false, fmt.Errorf("secretrotate: recovered and committed but clearing the staged rotation state failed: %w", err)
	}
	r.logf("Recovered a rotation the live service already accepted before a prior run was interrupted.")
	return st.PendingNext, true, nil
}

func requireVerify(spec Spec) error {
	if spec.Verify == nil {
		return errors.New("secretrotate: Spec.Verify is required because every operation observes the live credential first")
	}
	return nil
}

// resolveDeployedElsewhere accepts raced.Resolved after Verify confirms the live service uses it.
func (r rotator) resolveDeployedElsewhere(ctx context.Context, raced *deployRaceResolvedError) (string, error) {
	live, err := r.spec.Verify(ctx, raced.Resolved)
	if err != nil {
		return "", fmt.Errorf("secretrotate: %w, and verifying the raced value failed: %w", raced, err)
	}
	if !live {
		return "", raced
	}
	if err := r.store.clearRotationState(ctx); err != nil {
		return "", fmt.Errorf("secretrotate: %w, and clearing the stale rotation state failed: %w", raced, err)
	}
	r.logf("Deploy failed against a stale previous, but the Vault field already reflects a rotation completed elsewhere; accepting the raced value.")
	return raced.Resolved, nil
}

func (r rotator) resolveLiveCredential(ctx context.Context, candidates []string) (string, error) {
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		live, err := r.spec.Verify(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("secretrotate: verify a candidate credential: %w", err)
		}
		if live {
			return candidate, nil
		}
	}
	return "", ErrNoLiveCredential
}

func (r rotator) stageAndDeploy(ctx context.Context, read vaultField, live, next string) error {
	st := rotationState{Previous: live, PendingNext: next}
	if err := r.store.writeRotationState(ctx, st); err != nil {
		return err
	}
	deployErr := r.spec.Deploy(ctx, live, next)
	if deployErr == nil {
		r.logf("Credential rotated against the live service.")
		return nil
	}
	if current, ok := r.store.readField(ctx); ok && (!read.exists || current != read.value) {
		return &deployRaceResolvedError{Resolved: current, cause: deployErr}
	}
	return deployErr
}
