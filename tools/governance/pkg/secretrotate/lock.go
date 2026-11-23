package secretrotate

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

const (
	acquireLockMaxAttempts = 3
	defaultRotationLockTTL = 5 * time.Minute
	rotationLockTTLBuffer  = 30 * time.Second
)

// rotationLock is the advisory lock staged at "<field>_lock" during a rotation.
type rotationLock struct {
	Holder    string    `json:"holder"`
	ExpiresAt time.Time `json:"expires_at"`
}

// acquireLock stakes a CAS advisory lock and returns the written holder identifier.
func (s fieldStore) acquireLock(ctx context.Context) (string, error) {
	var lastErr error
	for range acquireLockMaxAttempts {
		// A missing document yields version 0 for the initial CAS write.
		doc, _ := s.readDocument(ctx)
		if lock, active := readActiveLock(doc, s.field); active {
			return "", fmt.Errorf("secretrotate: rotation aborted, %s owns the lock on %s/%s#%s until %s",
				lock.Holder, s.mount, s.path, s.field, lock.ExpiresAt.Format(time.RFC3339))
		}
		holder := fmt.Sprintf("rotate-%d", time.Now().UnixNano())
		raw, err := json.Marshal(rotationLock{Holder: holder, ExpiresAt: time.Now().Add(computeRotationLockTTL(ctx))})
		if err != nil {
			return "", fmt.Errorf("secretrotate: encode lock record: %w", err)
		}
		if err := s.writeFieldCAS(ctx, s.lockField(), string(raw), doc.version); err != nil {
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

// releaseLock clears the lock record when the stored entry still names holder.
func (s fieldStore) releaseLock(ctx context.Context, holder string) error {
	doc, ok := s.readDocument(ctx)
	if !ok {
		return nil
	}
	lock, ok := readRawLockRecord(doc, s.field)
	if !ok || lock.Holder != holder {
		return nil
	}
	writePath := s.dataPath()
	body := map[string]any{
		"data":    map[string]any{s.lockField(): nil},
		"options": map[string]any{"cas": doc.version},
	}
	if _, err := s.client.Logical().JSONMergePatch(ctx, writePath, body); err != nil {
		if isCASConflict(err) {
			return nil
		}
		return fmt.Errorf("secretrotate: release lock at %s: %w", writePath, err)
	}
	return nil
}

// checkNotLocked provides an advisory lock check. Only acquireLock guarantees exclusion.
func (s fieldStore) checkNotLocked(ctx context.Context) error {
	doc, ok := s.readDocument(ctx)
	if !ok {
		return nil
	}
	lock, active := readActiveLock(doc, s.field)
	if !active {
		return nil
	}
	return fmt.Errorf("secretrotate: rotation aborted, %s owns the lock on %s/%s#%s until %s",
		lock.Holder, s.mount, s.path, s.field, lock.ExpiresAt.Format(time.RFC3339))
}

func readActiveLock(doc documentSnapshot, field string) (rotationLock, bool) {
	lock, ok := readRawLockRecord(doc, field)
	if !ok || time.Now().After(lock.ExpiresAt) {
		return rotationLock{}, false
	}
	return lock, true
}

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

// computeRotationLockTTL extends the context deadline by rotationLockTTLBuffer when a deadline exists.
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

func acquireLock(ctx context.Context, client *vaultapi.Client, mount, path, field string) (string, error) {
	return newFieldStore(client, mount, path, field).acquireLock(ctx)
}

func releaseLock(ctx context.Context, client *vaultapi.Client, mount, path, field, holder string) error {
	return newFieldStore(client, mount, path, field).releaseLock(ctx, holder)
}

func checkNotLocked(ctx context.Context, client *vaultapi.Client, mount, path, field string) error {
	return newFieldStore(client, mount, path, field).checkNotLocked(ctx)
}
