package secretrotate

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestRotateOwnLockLifecycle covers the full lifecycle of the advisory lock Rotate stakes on
// itself: a concurrent call arriving while the lock is active MUST be rejected before reaching
// Apply, and a later, non-overlapping call MUST succeed once the lock is released.
func TestRotateOwnLockLifecycle(t *testing.T) {
	t.Run("rejects a concurrent call while the lock is active", testLockRejectsConcurrentCall)
	t.Run("releases the lock after completing", testLockReleasesAfterCompleting)
	t.Run("retries lock acquisition after a transient version conflict", testLockRetriesTransientConflict)
	t.Run("gives up after exhausting every retry against a persistent conflict", testLockGivesUpAfterPersistentConflict)
	t.Run("admits one holder when two callers interleave the check and the acquisition", testLockAdmitsOneInterleavedHolder)
	t.Run("leaves a lock staked by a different holder intact on release", testLockReleaseSpareForeignHolder)
}

// testLockAdmitsOneInterleavedHolder drives the interleaving Rotate itself performs: both callers
// clear checkNotLocked before either one reaches acquireLock. Exactly one caller MUST come away
// with the lock.
func testLockAdmitsOneInterleavedHolder(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	ctx := context.Background()

	if err := checkNotLocked(ctx, client, "secret", "app/infra", "password"); err != nil {
		t.Fatalf("first checkNotLocked: %v", err)
	}
	if err := checkNotLocked(ctx, client, "secret", "app/infra", "password"); err != nil {
		t.Fatalf("second checkNotLocked: %v", err)
	}

	first, firstErr := acquireLock(ctx, client, "secret", "app/infra", "password")
	second, secondErr := acquireLock(ctx, client, "secret", "app/infra", "password")

	if firstErr != nil {
		t.Fatalf("first acquireLock: %v", firstErr)
	}
	if secondErr == nil {
		t.Fatalf("both callers acquired the lock, holders %s and %s, want the second caller rejected", first, second)
	}
}

func testLockGivesUpAfterPersistentConflict(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	store.failCASConflicts = acquireLockMaxAttempts

	live := &liveService{current: "old-value"}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
		t.Fatal("Rotate: want error after exhausting every lock retry, got nil")
	}
	if len(live.deploys) != 0 {
		t.Error("Apply was called despite the lock never being acquired")
	}
}

func testLockRejectsConcurrentCall(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	live := &liveService{current: "old-value"}
	var concurrentErr error
	concurrentApplyCalled := false
	outer := live.bind(lockTestSpec())
	outer.Deploy = func(ctx context.Context, previous, next string) error {
		inner := live.bind(lockTestSpec())
		inner.Deploy = func(ctx context.Context, previous, next string) error {
			concurrentApplyCalled = true
			return nil
		}
		_, concurrentErr = Rotate(context.Background(), client, inner, nil)
		return live.deploy(ctx, previous, next)
	}

	if _, err := Rotate(context.Background(), client, outer, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if concurrentErr == nil {
		t.Fatal("concurrent Rotate: want error while the first call still owned the lock, got nil")
	}
	if concurrentApplyCalled {
		t.Error("concurrent Rotate reached Apply, want it rejected by the lock first")
	}
}

// testLockReleaseSpareForeignHolder covers the lock passing to a second holder after the TTL of
// the first holder elapses. The release issued by the first holder MUST leave the record alone.
func testLockReleaseSpareForeignHolder(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	ctx := context.Background()

	firstHolder, err := acquireLock(ctx, client, "secret", "app/infra", "password")
	if err != nil {
		t.Fatalf("acquireLock: %v", err)
	}
	foreign, err := json.Marshal(rotationLock{Holder: "other-process", ExpiresAt: time.Now().Add(1 * time.Minute)})
	if err != nil {
		t.Fatalf("Marshal foreign lock: %v", err)
	}
	seedField(t, client, "password_lock", string(foreign))

	if err := releaseLock(ctx, client, "secret", "app/infra", "password", firstHolder); err != nil {
		t.Fatalf("releaseLock: %v", err)
	}

	raw, ok := readField(ctx, client, "secret", "app/infra", "password_lock")
	if !ok {
		t.Fatal("the lock record was cleared, want the record staked by other-process left intact")
	}
	var staked rotationLock
	if err := json.Unmarshal([]byte(raw), &staked); err != nil {
		t.Fatalf("Unmarshal staked lock: %v", err)
	}
	if staked.Holder != "other-process" {
		t.Errorf("lock holder = %q, want %q", staked.Holder, "other-process")
	}
}

func testLockReleasesAfterCompleting(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	live := &liveService{current: "old-value"}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(context.Background(), client, spec, nil); err != nil {
		t.Fatalf("first Rotate: %v", err)
	}
	if _, err := Rotate(context.Background(), client, spec, nil); err != nil {
		t.Fatalf("second Rotate after the first released its lock: %v", err)
	}
}

func testLockRetriesTransientConflict(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	store.failCASConflicts = acquireLockMaxAttempts - 1

	live := &liveService{current: "old-value"}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(context.Background(), client, spec, nil); err != nil {
		t.Fatalf("Rotate: %v, want the retry to absorb the transient version conflicts", err)
	}
}
