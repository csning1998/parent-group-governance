package secretrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
)

// outsideWriteCase is one row of TestRotateResolvesAgainstAWriterOutsideThisRotation. liveValue
// names the single credential accepted by the fake live service. Each row thereby decides whether
// the value stored by the outside writer is genuinely live.
type outsideWriteCase struct {
	name             string
	storedByOutsider string
	liveValue        string
	wantValue        string
	wantErr          bool
}

// reReadCase is one row of TestRotateReReadsFieldStateAfterAcquiringTheLock. outOfBand is the
// value an outside writer stores at password immediately after the pre-lock read of Rotate
// observes the field as absent.
type reReadCase struct {
	name      string
	outOfBand string
}

// rotateCase is one row of TestRotateAuthenticatesWithTheVerifiedLiveCredential.
type rotateCase struct {
	name           string
	vaultValue     string
	hasVaultValue  bool
	factoryDefault string
	liveValue      string
	wantPrevious   string
	wantErr        error
}

// TestRotateAuthenticatesWithTheVerifiedLiveCredential covers every relation of the live credential to Vault.
func TestRotateAuthenticatesWithTheVerifiedLiveCredential(t *testing.T) {
	cases := []rotateCase{
		{name: "the vault value is live", vaultValue: "vault-value", hasVaultValue: true, liveValue: "vault-value", wantPrevious: "vault-value"},
		{name: "a rebuilt service has only the factory default", vaultValue: "vault-value", hasVaultValue: true, factoryDefault: "admin", liveValue: "admin", wantPrevious: "admin"},
		{name: "a rebuilt vault lacks a value and the service uses the factory default", factoryDefault: "admin", liveValue: "admin", wantPrevious: "admin"},
		{name: "the service accepts no known credential", vaultValue: "vault-value", hasVaultValue: true, factoryDefault: "admin", liveValue: "unknown", wantErr: ErrNoLiveCredential},
		{name: "a rebuilt vault lacks a value and the service lacks a factory default", liveValue: "unknown", wantErr: ErrNoLiveCredential},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestRotatePreservesStagedStateWhenTheRecoveryProbeIsInconclusive covers a staged pending value
// and a Verify which fails for a transport reason. The failure proves nothing about the live
// service. The staged record MUST survive and Rotate MUST refuse to mint over the record.
func TestRotatePreservesStagedStateWhenTheRecoveryProbeIsInconclusive(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	staged := rotationState{Previous: "old-value", PendingNext: "value-the-service-may-use"}
	if err := writeRotationState(context.Background(), client, "secret", "app/infra", "password", staged); err != nil {
		t.Fatalf("seed writeRotationState: %v", err)
	}

	live := &liveService{current: "old-value", verifyErr: errors.New("dial tcp 10.0.0.9:443: connect: connection refused")}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
		t.Fatal("Rotate: want an error while the state of the live service remains unknown, got nil")
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none", live.deploys)
	}

	_, pending, ok := readStagedRotationFields(t, client, "secret", "app/infra", "password")
	if !ok {
		t.Fatal("the staged rotation record was cleared, want the record preserved for the next run")
	}
	if pending != "value-the-service-may-use" {
		t.Errorf("staged pending_next = %q, want %q preserved", pending, "value-the-service-may-use")
	}
}

// TestRotatePreservesUnrelatedFieldsAtTheSamePath covers a Vault path shared with a writer this
// package does not control, such as a Terraform-managed field living alongside a credential.
// Rotate must patch its own field in place rather than overwrite the whole document.
func TestRotatePreservesUnrelatedFieldsAtTheSamePath(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "other_field", "keep-me")

	live := &liveService{current: "factory"}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = "factory"
	spec = live.bind(spec)

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	other, ok := readField(context.Background(), client, "secret", "app/infra", "other_field")
	if !ok || other != "keep-me" {
		t.Errorf("other_field = %q, ok=%v, want the unrelated field untouched", other, ok)
	}
	password, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || password != next || live.current != next {
		t.Errorf("password = %q, ok=%v, live = %q, want both %q", password, ok, live.current, next)
	}
}

// TestRotatePropagatesApplyFailureWithoutTouchingVault covers a failed Apply against a verified
// live credential: the failure MUST surface unchanged and the Vault value MUST remain untouched.
func TestRotatePropagatesApplyFailureWithoutTouchingVault(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "stale-value")

	live := &liveService{current: "stale-value", deployErr: errAuth}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(context.Background(), client, spec, nil); !errors.Is(err, errAuth) {
		t.Fatalf("Rotate: err = %v, want errAuth", err)
	}
	if len(live.deploys) != 1 || live.deploys[0][0] != "stale-value" {
		t.Errorf("deploys = %v, want exactly one attempt with the verified value", live.deploys)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != "stale-value" {
		t.Errorf("stored value = %q, ok=%v, want the pre-existing value untouched by a failed Apply", stored, ok)
	}
}

// TestRotateReReadsFieldStateAfterAcquiringTheLock covers a write landing, from outside this
// rotation, between the pre-lock read of Rotate and the point at which Rotate decides whether to
// call Apply. Authentication MUST proceed against the field value stored once the lock is staked.
func TestRotateReReadsFieldStateAfterAcquiringTheLock(t *testing.T) {
	cases := []reReadCase{
		{name: "a genuine credential appears out of band", outOfBand: "external-value"},
		{name: "an empty string appears out of band", outOfBand: ""},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestRotateRecoversWhenApplySucceededButCommitNeverRan covers the worst crash point. A prior run staged
// {previous, pending_next}. The live service accepted the Deploy. The process terminated before the final
// Vault commit. Rotate MUST verify and commit the staged pending value.
func TestRotateRecoversWhenApplySucceededButCommitNeverRan(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	if err := writeRotationState(context.Background(), client, "secret", "app/infra", "password",
		rotationState{Previous: "old-value", PendingNext: "actually-applied-value"}); err != nil {
		t.Fatalf("seed writeRotationState: %v", err)
	}

	live := &liveService{current: "actually-applied-value"}
	spec := live.bind(lockTestSpec())

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next != "actually-applied-value" {
		t.Errorf("Rotate returned %q, want the recovered pending_next %q instead of a freshly minted value", next, "actually-applied-value")
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want the recovery confirmed through Verify alone", live.deploys)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != "actually-applied-value" {
		t.Errorf("stored value = %q, ok=%v, want %q committed", stored, ok, "actually-applied-value")
	}
	if _, _, staged := readStagedRotationFields(t, client, "secret", "app/infra", "password"); staged {
		t.Error("the staged rotation record survived the recovery, want the record cleared")
	}
}

// TestRotateRefusesToApplyInUnsafeSituations covers two situations Rotate MUST refuse: a path
// an operator destroyed directly in Vault (data gone, version history still present), and a path
// locked by another in-flight rotation. Neither case may ever reach Apply.
func TestRotateRefusesToApplyInUnsafeSituations(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, client *vaultapi.Client, store *fakeKVv2)
	}{
		{
			name: "vault data was destroyed after having existed",
			setup: func(t *testing.T, client *vaultapi.Client, store *fakeKVv2) {
				if err := writeField(context.Background(), client, "secret", "app/infra", "password", "old-value"); err != nil {
					t.Fatalf("seed writeField: %v", err)
				}
				store.destroy("app/infra")
			},
		},
		{
			name: "another rotation owns the lock",
			setup: func(t *testing.T, client *vaultapi.Client, store *fakeKVv2) {
				if err := writeField(context.Background(), client, "secret", "app/infra", "password", "old-value"); err != nil {
					t.Fatalf("seed writeField: %v", err)
				}
				lockPayload, err := json.Marshal(map[string]string{
					"holder":     "other-process",
					"expires_at": time.Now().Add(1 * time.Minute).Format(time.RFC3339),
				})
				if err != nil {
					t.Fatalf("Marshal lock payload: %v", err)
				}
				if err := writeField(context.Background(), client, "secret", "app/infra", "password_lock", string(lockPayload)); err != nil {
					t.Fatalf("seed lock: %v", err)
				}
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, client, store := newFakeKVv2Server(t)
			defer srv.Close()
			c.setup(t, client, store)

			live := &liveService{current: "old-value"}
			spec := live.bind(lockTestSpec())

			if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
				t.Fatal("Rotate: want error, got nil")
			}
			if len(live.deploys) != 0 {
				t.Error("Apply was called, want Rotate to refuse before reaching the live service")
			}
		})
	}
}

// TestRotateRequiresAVerifyFunction covers a Spec without a way to observe the live service.
// Rotate MUST refuse before touching the service or Vault.
func TestRotateRequiresAVerifyFunction(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	live := &liveService{current: "old-value"}
	spec := live.bind(lockTestSpec())
	spec.Verify = nil

	if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
		t.Fatal("Rotate: want an error for a Spec without Verify, got nil")
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none", live.deploys)
	}
}

// TestRotateResolvesAgainstAWriterOutsideThisRotation covers an out-of-band write changing the
// Vault field mid-rotation. Rotate MUST confirm the live service uses the raced-in value before
// accepting the raced-in value, and MUST NOT report an unverified value as a rotation.
func TestRotateResolvesAgainstAWriterOutsideThisRotation(t *testing.T) {
	cases := []outsideWriteCase{
		{
			name:             "accepts the raced-in value once the live service confirms it",
			storedByOutsider: "raced-in-value",
			liveValue:        "raced-in-value",
			wantValue:        "raced-in-value",
		},
		{
			name:             "refuses a raced-in value the live service never accepted",
			storedByOutsider: "garbage-never-applied",
			liveValue:        "something-else-entirely",
			wantErr:          true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestRotateRetriesVaultWriteAfterApplySucceeds covers failure point B: Apply already changed
// the live credential to a known value. The Vault write MUST retry rather than surface a bare
// error, after which the stale value would be left stored in Vault.
func TestRotateRetriesVaultWriteAfterApplySucceeds(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	store.failWritesRemaining = 2

	live := &liveService{current: "factory"}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = "factory"
	spec = live.bind(spec)

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v, want the retry to absorb the two transient write failures", err)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != next {
		t.Errorf("stored value = %q, ok=%v, want %q", stored, ok, next)
	}
}

// TestRotateStagesPendingStateBeforeApplyingToTheLiveService covers the Write-Ahead staging
// step: Rotate MUST persist {previous, pending_next} to Vault before calling Apply. Enough state
// MUST remain in Vault for a mid-flight crash to be recovered by the next run.
func TestRotateStagesPendingStateBeforeApplyingToTheLiveService(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	live := &liveService{current: "old-value"}
	spec := live.bind(lockTestSpec())
	var stagedPrevious, stagedPendingNext string
	var stagedOK bool
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		stagedPrevious, stagedPendingNext, stagedOK = readStagedRotationFields(t, client, "secret", "app/infra", "password")
		return live.deploy(ctx, previous, next)
	}

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !stagedOK {
		t.Fatal("no staged rotation state was visible in Vault at the moment Apply ran")
	}
	if stagedPrevious != "old-value" {
		t.Errorf("staged previous = %q, want %q", stagedPrevious, "old-value")
	}
	if stagedPendingNext != next {
		t.Errorf("staged pending_next = %q, want %q (the value Rotate ultimately returned)", stagedPendingNext, next)
	}
}

func (c outsideWriteCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	outsiderWrote := false
	spec := lockTestSpec()
	spec.Verify = func(ctx context.Context, secret string) (bool, error) {
		return secret == c.liveValue || (secret == "old-value" && !outsiderWrote), nil
	}
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		outsiderWrote = true
		if previous == "old-value" {
			if err := writeField(context.Background(), client, "secret", "app/infra", "password", c.storedByOutsider); err != nil {
				t.Fatalf("simulate an out-of-band write: %v", err)
			}
		}
		if previous == c.liveValue {
			return nil
		}
		return fmt.Errorf("%w: test", ErrAuthRejected)
	}

	got, err := Rotate(context.Background(), client, spec, nil)
	if c.wantErr {
		if err == nil {
			t.Fatalf("Rotate returned %q with no error, want a value never validated against the live service to be refused", got)
		}
		return
	}
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if got != c.wantValue {
		t.Errorf("Rotate returned %q, want %q", got, c.wantValue)
	}
}

func (c reReadCase) run(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	ctx := context.Background()

	store.afterRequest = map[int]func(){
		1: func() {
			if err := writeField(ctx, client, "secret", "app/infra", "password", c.outOfBand); err != nil {
				t.Fatalf("simulate an out-of-band write: %v", err)
			}
		},
	}

	live := &liveService{current: c.outOfBand}
	spec := live.bind(lockTestSpec())

	if _, err := Rotate(ctx, client, spec, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	attempts := make([]string, 0, len(live.deploys))
	for _, d := range live.deploys {
		attempts = append(attempts, d[0])
	}
	if len(attempts) != 1 || attempts[0] != c.outOfBand {
		t.Errorf("Apply attempts = %v, want exactly one call authenticated with %q, the value an outside writer stored after the initial read observed the field as absent", attempts, c.outOfBand)
	}
}

func (c rotateCase) assertRejected(t *testing.T, err error, live *liveService, stored string, storedOK bool) {
	t.Helper()
	if !errors.Is(err, c.wantErr) {
		t.Fatalf("Rotate: err = %v, want %v", err, c.wantErr)
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none", live.deploys)
	}
	if storedOK != c.hasVaultValue || stored != c.vaultValue {
		t.Errorf("stored = %q, ok=%v, want Vault untouched", stored, storedOK)
	}
}

func (c rotateCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	if c.hasVaultValue {
		seedField(t, client, "password", c.vaultValue)
	}
	live := &liveService{current: c.liveValue}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = c.factoryDefault
	spec = live.bind(spec)

	next, err := Rotate(context.Background(), client, spec, nil)
	stored, storedOK := readField(context.Background(), client, "secret", "app/infra", "password")
	if c.wantErr != nil {
		c.assertRejected(t, err, live, stored, storedOK)
		return
	}
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(live.deploys) != 1 || live.deploys[0] != [2]string{c.wantPrevious, next} {
		t.Errorf("deploys = %v, want one Deploy(%q, next)", live.deploys, c.wantPrevious)
	}
	if !storedOK || stored != next || live.current != next {
		t.Errorf("stored = %q, live = %q, want both %q", stored, live.current, next)
	}
}
