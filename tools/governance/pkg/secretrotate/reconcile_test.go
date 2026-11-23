package secretrotate

import (
	"context"
	"errors"
	"slices"
	"testing"
)

// reconcileCase is one row of TestReconcileResolvesTheLiveCredentialBeforeDeploying.
type reconcileCase struct {
	name         string
	staged       string
	liveValue    string
	operator     string
	wantPrevious string
	wantErr      error
}

// TestReconcileAppliesVaultStoredValueAsNext covers applying a value already stored in Vault to
// a drifted live service, given the actual current credential of the live service.
func TestReconcileAppliesVaultStoredValueAsNext(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")

	live := &liveService{current: "live-value"}
	spec := live.bind(lockTestSpec())

	if err := Reconcile(context.Background(), client, spec, "live-value"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(live.deploys) != 1 || live.deploys[0] != [2]string{"live-value", "vault-value"} {
		t.Errorf("deploys = %v, want one Deploy(live-value, vault-value)", live.deploys)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != "vault-value" {
		t.Errorf("stored value = %q, ok=%v, want the Vault value left unchanged", stored, ok)
	}
}

// TestReconcileFailsWhenNoValueExistsInVault covers the case with nothing yet to push: the
// field does not exist in Vault yet, and Apply is never called.
func TestReconcileFailsWhenNoValueExistsInVault(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	live := &liveService{current: "live-value"}
	spec := live.bind(lockTestSpec())

	if err := Reconcile(context.Background(), client, spec, "live-value"); err == nil {
		t.Fatal("Reconcile: want error, got nil")
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none with nothing in Vault to push", live.deploys)
	}
}

// TestReconcileIsANoOpWhenTheServiceAlreadyAcceptsTheVaultValue covers a service already in sync.
// Reconcile MUST NOT call Deploy because some services reject a change to the same password.
func TestReconcileIsANoOpWhenTheServiceAlreadyAcceptsTheVaultValue(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")

	live := &liveService{current: "vault-value"}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = "admin"
	spec = live.bind(spec)

	if err := Reconcile(context.Background(), client, spec, ""); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none for a service already in sync", live.deploys)
	}
}

// TestReconcilePropagatesApplyFailure covers a Deploy failure against a verified live credential:
// Reconcile returns the failure unchanged.
func TestReconcilePropagatesApplyFailure(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")

	live := &liveService{current: "live-value", deployErr: errAuth}
	spec := live.bind(lockTestSpec())

	if err := Reconcile(context.Background(), client, spec, "live-value"); !errors.Is(err, errAuth) {
		t.Errorf("Reconcile: err = %v, want errAuth", err)
	}
}

// TestReconcileResolvesTheLiveCredentialBeforeDeploying covers an operator who leaves previous blank.
func TestReconcileResolvesTheLiveCredentialBeforeDeploying(t *testing.T) {
	cases := []reconcileCase{
		{name: "the factory default is live", liveValue: "admin", wantPrevious: "admin"},
		{name: "an interrupted rotation left the staged value live", staged: "pending-value", liveValue: "pending-value", wantPrevious: "pending-value"},
		{name: "the operator supplies the live value", operator: "typed-value", liveValue: "typed-value", wantPrevious: "typed-value"},
		{name: "the operator supplies a value rejected by the service", operator: "typed-value", liveValue: "admin", wantErr: ErrNoLiveCredential},
		{name: "no candidate is live", liveValue: "unknown", wantErr: ErrNoLiveCredential},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestReconcileStopsWhenVerifyIsInconclusive covers a transport failure of Verify. The transport failure
// does not prove the state of the live credential. Reconcile MUST stop before Deploy.
func TestReconcileStopsWhenVerifyIsInconclusive(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")

	transport := errors.New("dial tcp 10.0.0.9:443: connect: connection refused")
	live := &liveService{current: "admin", verifyErr: transport}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = "admin"
	spec = live.bind(spec)

	if err := Reconcile(context.Background(), client, spec, ""); !errors.Is(err, transport) {
		t.Fatalf("Reconcile: err = %v, want the transport failure", err)
	}
	if len(live.deploys) != 0 {
		t.Errorf("deploys = %v, want none", live.deploys)
	}
}

// TestReconcileTreatsStoredEmptyStringAsAValidNext covers a Vault field with the value "".
// An empty string is distinct from an absent field. Reconcile MUST still deploy the stored empty string.
func TestReconcileTreatsStoredEmptyStringAsAValidNext(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "")

	live := &liveService{current: "live-value"}
	spec := live.bind(lockTestSpec())

	if err := Reconcile(context.Background(), client, spec, "live-value"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(live.deploys) != 1 || live.deploys[0] != [2]string{"live-value", ""} {
		t.Errorf("deploys = %v, want one Deploy(live-value, \"\")", live.deploys)
	}
}

func (c reconcileCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")
	if c.staged != "" {
		staged := rotationState{Previous: "vault-value", PendingNext: c.staged}
		err := writeRotationState(context.Background(), client, "secret", "app/infra", "password", staged)
		if err != nil {
			t.Fatalf("seed writeRotationState: %v", err)
		}
	}
	live := &liveService{current: c.liveValue}
	spec := lockTestSpec()
	spec.FactoryDefaultPassword = "admin"
	spec = live.bind(spec)

	err := Reconcile(context.Background(), client, spec, c.operator)
	if !errors.Is(err, c.wantErr) {
		t.Fatalf("Reconcile: err = %v, want %v", err, c.wantErr)
	}
	want := [][2]string{{c.wantPrevious, "vault-value"}}
	if c.wantErr != nil {
		want = nil
	}
	if !slices.Equal(live.deploys, want) {
		t.Errorf("deploys = %v, want %v", live.deploys, want)
	}
}
