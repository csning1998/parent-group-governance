// Package secretrotate rotates a Vault-backed service credential.
// Refer to docs/secretrotate-design.md for the design.
package secretrotate

import (
	"context"
	"errors"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretgen"
)

// ErrAuthRejected marks a DeployFunc failure attributed to previous itself.
var ErrAuthRejected = errors.New("secretrotate: the live service rejected the previous credential")

// ErrNoLiveCredential marks a live service which accepts none of the candidate credentials.
var ErrNoLiveCredential = errors.New("secretrotate: the live service accepts none of the known credentials")

// DeployFunc deploys a rotated secret against the target service, authenticating with previous.
// An implementation MUST wrap ErrAuthRejected when the service rejects previous.
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

	// FactoryDefaultPassword is the credential of a rebuilt service, which Rotate and Reconcile verify as a candidate.
	FactoryDefaultPassword string
}

// VerifyFunc reports whether the live service accepts secret, without changing the service.
// An implementation MUST return an error, never false, for an answer which proves nothing.
type VerifyFunc func(ctx context.Context, secret string) (bool, error)

// deployRaceResolvedError signals that Deploy failed only because a writer outside this rotation
// already changed the target field before Deploy ran.
type deployRaceResolvedError struct {
	Resolved string
	cause    error
}

// documentSnapshot is one consistent view of a KV-v2 document.
type documentSnapshot struct {
	fields  map[string]any
	version int
}

// rotationLock is the advisory lock Rotate stages at "<field>_lock" for the duration of one rotation.
type rotationLock struct {
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

// rotationState is the Write-Ahead record Rotate stages at "<field>_rotation" before calling
// Apply.
type rotationState struct {
	Previous    string `json:"previous"`
	PendingNext string `json:"pending_next"`
}

// vaultField is the value of the rotated field which Rotate read under the lock.
type vaultField struct {
	value  string
	exists bool
}

// Exists reports whether Vault already holds a value for spec.
func Exists(ctx context.Context, client *vaultapi.Client, spec Spec) bool {
	_, ok := readField(ctx, client, spec.Mount, spec.Path, spec.Field)
	return ok
}

// Reconcile pushes the value Vault already holds for spec out to a drifted live service, never
// generating a value and never writing to Vault. An operator value replaces every other candidate.
func Reconcile(ctx context.Context, client *vaultapi.Client, spec Spec, operatorSupplied string) error {
	if err := requireVerify(spec); err != nil {
		return err
	}
	next, ok := readField(ctx, client, spec.Mount, spec.Path, spec.Field)
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
		if st, staged := readRotationState(ctx, client, spec.Mount, spec.Path, spec.Field); staged {
			candidates = append(candidates, st.PendingNext)
		}
		if spec.FactoryDefaultPassword != "" {
			candidates = append(candidates, spec.FactoryDefaultPassword)
		}
	}
	live, err := resolveLiveCredential(ctx, spec, candidates)
	if err != nil {
		return err
	}
	return spec.Deploy(ctx, live, next)
}

// Rotate applies Spec against client: verify the live credential, generate a replacement,
// deploy the replacement via Spec.Deploy, and on success persist and return the replacement.
// A failed Deploy is returned unchanged and Vault is left untouched.
func Rotate(ctx context.Context, client *vaultapi.Client, spec Spec, log func(string)) (string, error) {
	if err := requireVerify(spec); err != nil {
		return "", err
	}
	_, existedBeforeLock := readField(ctx, client, spec.Mount, spec.Path, spec.Field)
	if !existedBeforeLock && isPathDestroyedOutOfBand(ctx, client, spec.Mount, spec.Path) {
		return "", fmt.Errorf("secretrotate: %s/%s held data before and now reads back empty, refusing to mint a value the live service was never given", spec.Mount, spec.Path)
	}

	holder, err := acquireLock(ctx, client, spec.Mount, spec.Path, spec.Field)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := releaseLock(ctx, client, spec.Mount, spec.Path, spec.Field, holder); err != nil && log != nil {
			log("Warning: failed to release the rotation lock, the lock will expire at its own TTL: " + err.Error())
		}
	}()

	previous, exists := readField(ctx, client, spec.Mount, spec.Path, spec.Field)

	if recovered, ok, err := recoverPendingRotation(ctx, client, spec, log); err != nil || ok {
		return recovered, err
	}

	// A rebuilt service holds the factory default, and a rebuilt Vault holds no value at all.
	var candidates []string
	if exists {
		candidates = append(candidates, previous)
	}
	if spec.FactoryDefaultPassword != "" {
		candidates = append(candidates, spec.FactoryDefaultPassword)
	}
	live, err := resolveLiveCredential(ctx, spec, candidates)
	if err != nil {
		return "", err
	}

	next, err := secretgen.Generate(spec.Length, spec.Classes...)
	if err != nil {
		return "", err
	}
	return commitRotation(ctx, client, spec, vaultField{value: previous, exists: exists}, live, next, log)
}

func (e *deployRaceResolvedError) Error() string {
	return fmt.Sprintf("secretrotate: deploy failed against a stale previous, a concurrent write already resolved this credential: %v", e.cause)
}

func (e *deployRaceResolvedError) Unwrap() error { return e.cause }

// acquireLock stakes the claim of the current Rotate call on the lock, returning the holder identifier written.
func commitRotation(ctx context.Context, client *vaultapi.Client, spec Spec, read vaultField, live, next string, log func(string)) (string, error) {
	if err := stageAndDeploy(ctx, client, spec, read, live, next, log); err != nil {
		var raced *deployRaceResolvedError
		if errors.As(err, &raced) {
			return resolveDeployedElsewhere(ctx, client, spec, raced, log)
		}
		return "", err
	}

	if err := writeField(ctx, client, spec.Mount, spec.Path, spec.Field, next); err != nil {
		return "", fmt.Errorf("secretrotate: rotated but the Vault write failed, re-run to recover the staged value: %w", err)
	}
	if err := clearRotationState(ctx, client, spec.Mount, spec.Path, spec.Field); err != nil {
		return "", fmt.Errorf("secretrotate: rotated and committed but clearing the staged rotation state failed: %w", err)
	}
	if log != nil {
		log("New value stored at " + spec.Mount + "/" + spec.Path + "#" + spec.Field + ".")
	}
	return next, nil
}

// recoverPendingRotation verifies the pending value staged by a prior, interrupted Rotate call.
// Only a verified rejection falls through to a normal rotation.
func recoverPendingRotation(ctx context.Context, client *vaultapi.Client, spec Spec, log func(string)) (string, bool, error) {
	st, ok := readRotationState(ctx, client, spec.Mount, spec.Path, spec.Field)
	if !ok {
		return "", false, nil
	}
	live, err := spec.Verify(ctx, st.PendingNext)
	if err != nil {
		return "", false, fmt.Errorf("secretrotate: verify the staged pending value: %w", err)
	}
	if !live {
		return "", false, nil
	}
	if err := writeField(ctx, client, spec.Mount, spec.Path, spec.Field, st.PendingNext); err != nil {
		return "", false, fmt.Errorf("secretrotate: recovered pending value but the Vault commit failed: %w", err)
	}
	if err := clearRotationState(ctx, client, spec.Mount, spec.Path, spec.Field); err != nil {
		return "", false, fmt.Errorf("secretrotate: recovered and committed but clearing the staged rotation state failed: %w", err)
	}
	if log != nil {
		log("Recovered a rotation the live service already accepted before a prior run was interrupted.")
	}
	return st.PendingNext, true, nil
}

func requireVerify(spec Spec) error {
	if spec.Verify == nil {
		return errors.New("secretrotate: Spec.Verify is required, since every operation observes the live credential first")
	}
	return nil
}

// resolveDeployedElsewhere accepts raced.Resolved only after Verify confirms the live service
// holds that same value.
func resolveDeployedElsewhere(ctx context.Context, client *vaultapi.Client, spec Spec, raced *deployRaceResolvedError, log func(string)) (string, error) {
	live, err := spec.Verify(ctx, raced.Resolved)
	if err != nil {
		return "", fmt.Errorf("secretrotate: %w, and verifying the raced value failed: %w", raced, err)
	}
	if !live {
		return "", raced
	}
	if err := clearRotationState(ctx, client, spec.Mount, spec.Path, spec.Field); err != nil {
		return "", fmt.Errorf("secretrotate: %w, and clearing the stale rotation state failed: %w", raced, err)
	}
	if log != nil {
		log("Deploy failed against a stale previous, but the Vault field already reflects a rotation completed elsewhere; accepting that value.")
	}
	return raced.Resolved, nil
}

// resolveLiveCredential returns the first candidate which the live service accepts.
func resolveLiveCredential(ctx context.Context, spec Spec, candidates []string) (string, error) {
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		live, err := spec.Verify(ctx, candidate)
		if err != nil {
			return "", fmt.Errorf("secretrotate: verify a candidate credential: %w", err)
		}
		if live {
			return candidate, nil
		}
	}
	return "", ErrNoLiveCredential
}

func stageAndDeploy(ctx context.Context, client *vaultapi.Client, spec Spec, read vaultField, live, next string, log func(string)) error {
	st := rotationState{Previous: live, PendingNext: next}
	if err := writeRotationState(ctx, client, spec.Mount, spec.Path, spec.Field, st); err != nil {
		return err
	}
	deployErr := spec.Deploy(ctx, live, next)
	if deployErr == nil {
		if log != nil {
			log("Credential rotated against the live service.")
		}
		return nil
	}
	if current, ok := readField(ctx, client, spec.Mount, spec.Path, spec.Field); ok && (!read.exists || current != read.value) {
		return &deployRaceResolvedError{Resolved: current, cause: deployErr}
	}
	return deployErr
}
