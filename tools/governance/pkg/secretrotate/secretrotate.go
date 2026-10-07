// Package secretrotate rotates a Vault-backed service credential.
// Refer to docs/secretrotate-design.md for the design.
package secretrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
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

// VerifyFunc reports whether the live service accepts secret, without changing the service.
// An implementation MUST return an error, never false, for an answer which proves nothing.
type VerifyFunc func(ctx context.Context, secret string) (bool, error)

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

func requireVerify(spec Spec) error {
	if spec.Verify == nil {
		return errors.New("secretrotate: Spec.Verify is required, since every operation observes the live credential first")
	}
	return nil
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

func resolveDataPath(mount, path string) string { return mount + "/data/" + path }

// documentSnapshot is one consistent view of a KV-v2 document.
type documentSnapshot struct {
	fields  map[string]interface{}
	version int
}

func readDocument(ctx context.Context, client *vaultapi.Client, mount, path string) (documentSnapshot, bool) {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	if err != nil || secret == nil {
		return documentSnapshot{}, false
	}
	fields, _ := secret.Data["data"].(map[string]interface{})
	version := 0
	if meta, ok := secret.Data["metadata"].(map[string]interface{}); ok {
		version = parseVersionNumber(meta["version"])
	}
	return documentSnapshot{fields: fields, version: version}, true
}

func parseVersionNumber(raw interface{}) int {
	switch v := raw.(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	default:
		return 0
	}
}

func (d documentSnapshot) readStringField(name string) (string, bool) {
	value, ok := d.fields[name].(string)
	return value, ok
}

func readField(ctx context.Context, client *vaultapi.Client, mount, path, field string) (value string, ok bool) {
	doc, exists := readDocument(ctx, client, mount, path)
	if !exists {
		return "", false
	}
	return doc.readStringField(field)
}

func hasDocument(ctx context.Context, client *vaultapi.Client, mount, path string) bool {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	return err == nil && secret != nil
}

func isMissingDocument(err error) bool {
	var respErr *vaultapi.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

// patchOrInitDocument patches body into mount/path, falling back to an outright create only when the
// patch is rejected because no document exists yet.
func patchOrInitDocument(ctx context.Context, client *vaultapi.Client, mount, path string, body map[string]interface{}) error {
	writePath := resolveDataPath(mount, path)
	if _, err := client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		if !isMissingDocument(err) {
			return fmt.Errorf("secretrotate: patch %s: %w", writePath, err)
		}
		if _, err := client.Logical().WriteWithContext(ctx, writePath, body); err != nil {
			return fmt.Errorf("secretrotate: write %s: %w", writePath, err)
		}
	}
	return nil
}

func writeField(ctx context.Context, client *vaultapi.Client, mount, path, field, value string) error {
	return patchOrInitDocument(ctx, client, mount, path, map[string]interface{}{"data": map[string]interface{}{field: value}})
}

// rotationState is the Write-Ahead record Rotate stages at "<field>_rotation" before calling
// Apply.
type rotationState struct {
	Previous    string `json:"previous"`
	PendingNext string `json:"pending_next"`
}

func formatRotationStateField(field string) string { return field + "_rotation" }

func readRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string) (rotationState, bool) {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	if err != nil || secret == nil {
		return rotationState{}, false
	}
	data, _ := secret.Data["data"].(map[string]interface{})
	raw, ok := data[formatRotationStateField(field)].(string)
	if !ok {
		return rotationState{}, false
	}
	var st rotationState
	if err := json.Unmarshal([]byte(raw), &st); err != nil {
		return rotationState{}, false
	}
	return st, true
}

// writeRotationState stores the record as a JSON string, since Terraform reads every field of the path as a string.
func writeRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string, st rotationState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return fmt.Errorf("secretrotate: encode rotation state: %w", err)
	}
	body := map[string]interface{}{"data": map[string]interface{}{
		formatRotationStateField(field): string(raw),
	}}
	if err := patchOrInitDocument(ctx, client, mount, path, body); err != nil {
		return fmt.Errorf("secretrotate: stage rotation state at %s: %w", resolveDataPath(mount, path), err)
	}
	return nil
}

func clearRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string) error {
	writePath := resolveDataPath(mount, path)
	body := map[string]interface{}{"data": map[string]interface{}{formatRotationStateField(field): nil}}
	if _, err := client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		return fmt.Errorf("secretrotate: clear rotation state at %s: %w", writePath, err)
	}
	return nil
}

// rotationLock is the advisory lock Rotate stages at "<field>_lock" for the duration of one rotation.
type rotationLock struct {
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

func parseLock(raw string) (rotationLock, bool) {
	var lock rotationLock
	if err := json.Unmarshal([]byte(raw), &lock); err != nil {
		return rotationLock{}, false
	}
	return lock, true
}

// readRawLockRecord reads the raw lock record staked at field, ignoring expiry.
func readRawLockRecord(doc documentSnapshot, field string) (rotationLock, bool) {
	raw, ok := doc.readStringField(field + "_lock")
	if !ok {
		return rotationLock{}, false
	}
	return parseLock(raw)
}

// readActiveLock reports the unexpired lock a different rotation left at field, within doc.
func readActiveLock(doc documentSnapshot, field string) (rotationLock, bool) {
	lock, ok := readRawLockRecord(doc, field)
	if !ok || time.Now().After(lock.ExpiresAt) {
		return rotationLock{}, false
	}
	return lock, true
}

// checkNotLocked is a non-authoritative peek. acquireLock alone provides exclusion.
func checkNotLocked(ctx context.Context, client *vaultapi.Client, mount, path, field string) error {
	doc, ok := readDocument(ctx, client, mount, path)
	if !ok {
		return nil
	}
	lock, held := readActiveLock(doc, field)
	if !held {
		return nil
	}
	return fmt.Errorf("secretrotate: rotation aborted, %s holds the lock on %s/%s#%s until %s",
		lock.Holder, mount, path, field, lock.ExpiresAt.Format(time.RFC3339))
}

const defaultRotationLockTTL = 5 * time.Minute

const rotationLockTTLBuffer = 30 * time.Second

// computeRotationLockTTL sizes the lock against a deadline carried by ctx when one is present.
func computeRotationLockTTL(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultRotationLockTTL
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return rotationLockTTLBuffer
	}
	return remaining + rotationLockTTLBuffer
}

const casConflictSubstring = "check-and-set parameter did not match the current version"

func isCASConflict(err error) bool {
	if err == nil {
		return false
	}
	var respErr *vaultapi.ResponseError
	if errors.As(err, &respErr) {
		if respErr.StatusCode != http.StatusBadRequest {
			return false
		}
		for _, msg := range respErr.Errors {
			if strings.Contains(msg, casConflictSubstring) {
				return true
			}
		}
		return false
	}
	return strings.Contains(err.Error(), casConflictSubstring)
}

func writeFieldCAS(ctx context.Context, client *vaultapi.Client, mount, path, field, value string, version int) error {
	writePath := resolveDataPath(mount, path)
	body := map[string]interface{}{
		"data":    map[string]interface{}{field: value},
		"options": map[string]interface{}{"cas": version},
	}
	if version > 0 {
		_, err := client.Logical().JSONMergePatch(ctx, writePath, body)
		return err
	}
	_, err := client.Logical().WriteWithContext(ctx, writePath, body)
	return err
}

const acquireLockMaxAttempts = 3

// acquireLock stakes the claim of the current Rotate call on the lock, returning the holder identifier written.
func acquireLock(ctx context.Context, client *vaultapi.Client, mount, path, field string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < acquireLockMaxAttempts; attempt++ {
		doc, _ := readDocument(ctx, client, mount, path)
		if lock, held := readActiveLock(doc, field); held {
			return "", fmt.Errorf("secretrotate: rotation aborted, %s holds the lock on %s/%s#%s until %s",
				lock.Holder, mount, path, field, lock.ExpiresAt.Format(time.RFC3339))
		}
		holder := fmt.Sprintf("rotate-%d", time.Now().UnixNano())
		raw, err := json.Marshal(rotationLock{Holder: holder, ExpiresAt: time.Now().Add(computeRotationLockTTL(ctx))})
		if err != nil {
			return "", fmt.Errorf("secretrotate: encode lock record: %w", err)
		}
		if err := writeFieldCAS(ctx, client, mount, path, field+"_lock", string(raw), doc.version); err != nil {
			if !isCASConflict(err) {
				return "", fmt.Errorf("secretrotate: acquire lock: %w", err)
			}
			lastErr = err
			continue
		}
		return holder, nil
	}
	return "", fmt.Errorf("secretrotate: acquire lock: gave up after %d version conflicts: %w", acquireLockMaxAttempts, lastErr)
}

// releaseLock clears the lock at mount/path/field only when the record staked there still names holder.
func releaseLock(ctx context.Context, client *vaultapi.Client, mount, path, field, holder string) error {
	doc, ok := readDocument(ctx, client, mount, path)
	if !ok {
		return nil
	}
	lock, ok := readRawLockRecord(doc, field)
	if !ok || lock.Holder != holder {
		return nil
	}
	writePath := resolveDataPath(mount, path)
	body := map[string]interface{}{
		"data":    map[string]interface{}{field + "_lock": nil},
		"options": map[string]interface{}{"cas": doc.version},
	}
	if _, err := client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		if isCASConflict(err) {
			return nil
		}
		return fmt.Errorf("secretrotate: release lock at %s: %w", writePath, err)
	}
	return nil
}

// hasVersionHistory reports whether path once held data. Callers MUST also confirm hasDocument is
// false before treating this as a destroyed field.
func hasVersionHistory(ctx context.Context, client *vaultapi.Client, mount, path string) bool {
	secret, err := client.Logical().ReadWithContext(ctx, mount+"/metadata/"+path)
	if err != nil || secret == nil {
		return false
	}
	return parseVersionNumber(secret.Data["current_version"]) > 0
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

// vaultField is the value of the rotated field which Rotate read under the lock.
type vaultField struct {
	value  string
	exists bool
}

func isPathDestroyedOutOfBand(ctx context.Context, client *vaultapi.Client, mount, path string) bool {
	return !hasDocument(ctx, client, mount, path) && hasVersionHistory(ctx, client, mount, path)
}

// applyRaceResolvedError signals that Apply failed only because a writer outside this rotation
// already changed the target field before Apply ran.
type applyRaceResolvedError struct {
	Resolved string
	cause    error
}

func (e *applyRaceResolvedError) Error() string {
	return fmt.Sprintf("secretrotate: apply failed against a stale previous, a concurrent write already resolved this credential: %v", e.cause)
}

func (e *applyRaceResolvedError) Unwrap() error { return e.cause }

func stageAndApply(ctx context.Context, client *vaultapi.Client, spec Spec, read vaultField, live, next string, log func(string)) error {
	st := rotationState{Previous: live, PendingNext: next}
	if err := writeRotationState(ctx, client, spec.Mount, spec.Path, spec.Field, st); err != nil {
		return err
	}
	applyErr := spec.Deploy(ctx, live, next)
	if applyErr == nil {
		if log != nil {
			log("Credential rotated against the live service.")
		}
		return nil
	}
	if current, ok := readField(ctx, client, spec.Mount, spec.Path, spec.Field); ok && (!read.exists || current != read.value) {
		return &applyRaceResolvedError{Resolved: current, cause: applyErr}
	}
	return applyErr
}

func commitRotation(ctx context.Context, client *vaultapi.Client, spec Spec, read vaultField, live, next string, log func(string)) (string, error) {
	if err := stageAndApply(ctx, client, spec, read, live, next, log); err != nil {
		var raced *applyRaceResolvedError
		if errors.As(err, &raced) {
			return resolveAppliedElsewhere(ctx, client, spec, raced, log)
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

// resolveAppliedElsewhere accepts raced.Resolved only after Verify confirms the live service
// holds that same value.
func resolveAppliedElsewhere(ctx context.Context, client *vaultapi.Client, spec Spec, raced *applyRaceResolvedError, log func(string)) (string, error) {
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
		log("Apply failed against a stale previous, but the Vault field already reflects a rotation completed elsewhere; accepting that value.")
	}
	return raced.Resolved, nil
}
