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
)

const acquireLockMaxAttempts = 3

const casConflictSubstring = "check-and-set parameter did not match the current version"

const defaultRotationLockTTL = 5 * time.Minute

const rotationLockTTLBuffer = 30 * time.Second

// acquireLock stakes the claim of the current Rotate call on the lock, returning the holder identifier written.
func acquireLock(ctx context.Context, client *vaultapi.Client, mount, path, field string) (string, error) {
	var lastErr error
	for range acquireLockMaxAttempts {
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
	body := map[string]any{
		"data":    map[string]any{field + "_lock": nil},
		"options": map[string]any{"cas": doc.version},
	}
	if _, err := client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		if isCASConflict(err) {
			return nil
		}
		return fmt.Errorf("secretrotate: release lock at %s: %w", writePath, err)
	}
	return nil
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

// readActiveLock reports the unexpired lock a different rotation left at field, within doc.
func readActiveLock(doc documentSnapshot, field string) (rotationLock, bool) {
	lock, ok := readRawLockRecord(doc, field)
	if !ok || time.Now().After(lock.ExpiresAt) {
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

func parseLock(raw string) (rotationLock, bool) {
	var lock rotationLock
	if err := json.Unmarshal([]byte(raw), &lock); err != nil {
		return rotationLock{}, false
	}
	return lock, true
}

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

func readRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string) (rotationState, bool) {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	if err != nil || secret == nil {
		return rotationState{}, false
	}
	data, _ := secret.Data["data"].(map[string]any)
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
	body := map[string]any{"data": map[string]any{
		formatRotationStateField(field): string(raw),
	}}
	if err := patchOrInitDocument(ctx, client, mount, path, body); err != nil {
		return fmt.Errorf("secretrotate: stage rotation state at %s: %w", resolveDataPath(mount, path), err)
	}
	return nil
}

func clearRotationState(ctx context.Context, client *vaultapi.Client, mount, path, field string) error {
	writePath := resolveDataPath(mount, path)
	body := map[string]any{"data": map[string]any{formatRotationStateField(field): nil}}
	if _, err := client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		return fmt.Errorf("secretrotate: clear rotation state at %s: %w", writePath, err)
	}
	return nil
}

func formatRotationStateField(field string) string { return field + "_rotation" }

func readField(ctx context.Context, client *vaultapi.Client, mount, path, field string) (value string, ok bool) {
	doc, exists := readDocument(ctx, client, mount, path)
	if !exists {
		return "", false
	}
	return doc.readStringField(field)
}

func writeField(ctx context.Context, client *vaultapi.Client, mount, path, field, value string) error {
	return patchOrInitDocument(ctx, client, mount, path, map[string]any{"data": map[string]any{field: value}})
}

func writeFieldCAS(ctx context.Context, client *vaultapi.Client, mount, path, field, value string, version int) error {
	writePath := resolveDataPath(mount, path)
	body := map[string]any{
		"data":    map[string]any{field: value},
		"options": map[string]any{"cas": version},
	}
	if version > 0 {
		_, err := client.Logical().JSONMergePatch(ctx, writePath, body)
		return err
	}
	_, err := client.Logical().WriteWithContext(ctx, writePath, body)
	return err
}

func readDocument(ctx context.Context, client *vaultapi.Client, mount, path string) (documentSnapshot, bool) {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	if err != nil || secret == nil {
		return documentSnapshot{}, false
	}
	fields, _ := secret.Data["data"].(map[string]any)
	version := 0
	if meta, ok := secret.Data["metadata"].(map[string]any); ok {
		version = parseVersionNumber(meta["version"])
	}
	return documentSnapshot{fields: fields, version: version}, true
}

func (d documentSnapshot) readStringField(name string) (string, bool) {
	value, ok := d.fields[name].(string)
	return value, ok
}

// patchOrInitDocument patches body into mount/path, falling back to an outright create only when the
// patch is rejected because no document exists yet.
func patchOrInitDocument(ctx context.Context, client *vaultapi.Client, mount, path string, body map[string]any) error {
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

func hasDocument(ctx context.Context, client *vaultapi.Client, mount, path string) bool {
	secret, err := client.Logical().ReadWithContext(ctx, resolveDataPath(mount, path))
	return err == nil && secret != nil
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

func isPathDestroyedOutOfBand(ctx context.Context, client *vaultapi.Client, mount, path string) bool {
	return !hasDocument(ctx, client, mount, path) && hasVersionHistory(ctx, client, mount, path)
}

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

func isMissingDocument(err error) bool {
	var respErr *vaultapi.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

func parseVersionNumber(raw any) int {
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

func resolveDataPath(mount, path string) string { return mount + "/data/" + path }
