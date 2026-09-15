package secretrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretgen"
)

// fakeKVv2 is a minimal in-memory KV-v2 engine at mount "secret" backing an httptest server,
// letting Rotate run end-to-end in tests without a real Vault. everExisted survives a destroy
// call, matching how the real Vault metadata endpoint keeps version history after data is gone.
type fakeKVv2 struct {
	mu                  sync.Mutex
	data                map[string]map[string]interface{}
	version             map[string]int
	everExisted         map[string]bool
	failWritesRemaining int
	failCASConflicts    int
	requests            []string
	afterRequest        map[int]func()
}

// destroy removes the current data at path while leaving everExisted set, simulating `vault kv
// delete` / `vault kv destroy` against a path this package never touched directly.
func (s *fakeKVv2) destroy(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, path)
}

// recordRequest appends one "METHOD path" entry to the request log and fires any hook staged for
// the 1-based position at which the new entry lands. The hook runs after mu is released, letting
// the hook issue its own requests against the same server without self-deadlock.
func (s *fakeKVv2) recordRequest(method, path string) {
	s.mu.Lock()
	s.requests = append(s.requests, method+" "+path)
	hook := s.afterRequest[len(s.requests)]
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func newFakeKVv2Server(t *testing.T) (*httptest.Server, *vaultapi.Client, *fakeKVv2) {
	t.Helper()
	store := &fakeKVv2{
		data:        map[string]map[string]interface{}{},
		version:     map[string]int{},
		everExisted: map[string]bool{},
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer store.recordRequest(r.Method, r.URL.Path)
		if path, ok := trimFakeVaultPrefix(r.URL.Path, "/v1/secret/metadata/"); ok {
			store.handleMetadata(w, r, path)
			return
		}
		path, ok := trimFakeVaultPrefix(r.URL.Path, "/v1/secret/data/")
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Method {
		case http.MethodGet:
			store.handleGet(w, path)
		case http.MethodPut, http.MethodPost:
			store.handleWrite(w, r, path)
		case http.MethodPatch:
			store.handlePatch(w, r, path)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))

	cfg := vaultapi.DefaultConfig()
	cfg.Address = srv.URL
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return srv, client, store
}

func trimFakeVaultPrefix(path, prefix string) (string, bool) {
	if len(path) < len(prefix) || path[:len(prefix)] != prefix {
		return "", false
	}
	return path[len(prefix):], true
}

// fakeVaultPayload is the request body shape shared by the write and patch handlers of the fake
// server, holding the KV-v2 data map plus an optional check-and-set version requested by the
// caller.
type fakeVaultPayload struct {
	Data map[string]interface{} `json:"data"`
	Cas  *int                   `json:"cas"`
}

func decodeFakeVaultPayload(r *http.Request) (fakeVaultPayload, error) {
	body, _ := io.ReadAll(r.Body)
	var raw struct {
		Data    map[string]interface{} `json:"data"`
		Options struct {
			Cas *int `json:"cas"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fakeVaultPayload{}, err
	}
	return fakeVaultPayload{Data: raw.Data, Cas: raw.Options.Cas}, nil
}

// casConflictBody matches the error text a real Vault server returns for a check-and-set
// mismatch. isCASConflict in the production code matches against this same substring.
const casConflictBody = `{"errors":["check-and-set parameter did not match the current version"]}`

func (s *fakeKVv2) handleGet(w http.ResponseWriter, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fields, ok := s.data[path]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{
			"data":     fields,
			"metadata": map[string]interface{}{"version": s.version[path]},
		},
	})
}

// rejectCAS reports whether the write MUST be rejected as a check-and-set conflict: either a
// forced conflict staged by a test through failCASConflicts, or a version mismatch against the
// requested cas value. rejectCAS assumes the caller already holds s.mu.
func (s *fakeKVv2) rejectCAS(path string, cas *int) bool {
	if s.failCASConflicts > 0 {
		s.failCASConflicts--
		return true
	}
	return cas != nil && *cas != s.version[path]
}

func (s *fakeKVv2) handleWrite(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failWritesRemaining > 0 {
		s.failWritesRemaining--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	payload, err := decodeFakeVaultPayload(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.rejectCAS(path, payload.Cas) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(casConflictBody))
		return
	}
	s.data[path] = payload.Data
	s.version[path]++
	s.everExisted[path] = true
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
}

// handlePatch applies an RFC 7396 JSON merge patch, scoped to the "data" object only: fields
// already present at path survive, only the patched fields change.
func (s *fakeKVv2) handlePatch(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[path]; !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	payload, err := decodeFakeVaultPayload(r)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if s.rejectCAS(path, payload.Cas) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(casConflictBody))
		return
	}
	merged := s.data[path]
	for k, v := range payload.Data {
		merged[k] = v
	}
	s.data[path] = merged
	s.version[path]++
	s.everExisted[path] = true
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{}})
}

// handleMetadata answers the Vault metadata endpoint: current_version stays positive once a
// path has ever held data, even after destroy deletes the data itself.
func (s *fakeKVv2) handleMetadata(w http.ResponseWriter, r *http.Request, path string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.everExisted[path] {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errors":[]}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"data": map[string]interface{}{"current_version": s.version[path]},
	})
}

var errAuth = errors.New("auth rejected")

// readStagedRotationFields reads the Write-Ahead staging document Rotate is expected to persist
// at "<field>_rotation" before calling Apply. The test talks to the fake server directly, since
// the point of this test is to force a matching production helper into being.
func readStagedRotationFields(t *testing.T, client *vaultapi.Client, mount, path, field string) (previous, pendingNext string, ok bool) {
	t.Helper()
	secret, err := client.Logical().ReadWithContext(context.Background(), mount+"/data/"+path)
	if err != nil || secret == nil {
		return "", "", false
	}
	data, _ := secret.Data["data"].(map[string]interface{})
	staging, ok := data[field+"_rotation"].(map[string]interface{})
	if !ok {
		return "", "", false
	}
	previous, _ = staging["previous"].(string)
	pendingNext, _ = staging["pending_next"].(string)
	return previous, pendingNext, true
}

// TestRotatePreservesUnrelatedFieldsAtTheSamePath covers a Vault path shared with a writer this
// package does not control, such as a Terraform-managed field living alongside a credential.
// Rotate must patch its own field in place rather than overwrite the whole document.
func TestRotatePreservesUnrelatedFieldsAtTheSamePath(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "other_field", "keep-me"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			return nil
		},
	}

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}

	other, ok := readField(context.Background(), client, "secret", "app/infra", "other_field")
	if !ok || other != "keep-me" {
		t.Errorf("other_field = %q, ok=%v, want the unrelated field untouched", other, ok)
	}
	password, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || password != next {
		t.Errorf("password = %q, ok=%v, want %q", password, ok, next)
	}
}

// TestRotateStagesPendingStateBeforeApplyingToTheLiveService covers the Write-Ahead staging
// step: Rotate MUST persist {previous, pending_next} to Vault before calling Apply. Enough state
// MUST remain in Vault for a mid-flight crash to be recovered by the next run.
func TestRotateStagesPendingStateBeforeApplyingToTheLiveService(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "old-value"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	var stagedPrevious, stagedPendingNext string
	var stagedOK bool
	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			stagedPrevious, stagedPendingNext, stagedOK = readStagedRotationFields(t, client, "secret", "app/infra", "password")
			return nil
		},
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

// TestRotateSkipsApplyAndMintsDirectlyWhenNoPriorValueExists covers first-time creation: Vault
// does not hold a previous value, leaving no credential with which the live service call can be
// authenticated. Rotate mints a value straight into Vault instead of calling Apply.
func TestRotateSkipsApplyAndMintsDirectlyWhenNoPriorValueExists(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	applyCalled := false
	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			applyCalled = true
			return nil
		},
	}

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if applyCalled {
		t.Error("Apply was called on first creation, want it skipped")
	}
	if len(next) != 16 {
		t.Errorf("Rotate returned %q, want length 16", next)
	}

	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != next {
		t.Errorf("stored value = %q, ok=%v, want %q", stored, ok, next)
	}
}

// TestRotatePropagatesApplyFailureWithoutTouchingVault covers a failed Apply from both angles:
// the value read from Vault MUST be the exact and only previous guess offered, and a failed
// Apply MUST leave the pre-existing Vault value untouched.
func TestRotatePropagatesApplyFailureWithoutTouchingVault(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "stale-value"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	var attempts []string
	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			attempts = append(attempts, previous)
			return errAuth
		},
	}

	if _, err := Rotate(context.Background(), client, spec, nil); !errors.Is(err, errAuth) {
		t.Fatalf("Rotate: err = %v, want errAuth", err)
	}
	if len(attempts) != 1 || attempts[0] != "stale-value" {
		t.Errorf("attempts = %v, want exactly one attempt with the value read from Vault", attempts)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != "stale-value" {
		t.Errorf("stored value = %q, ok=%v, want the pre-existing value untouched by a failed Apply", stored, ok)
	}
}

func TestExistsReflectsWhetherVaultHoldsTheField(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	spec := Spec{Mount: "secret", Path: "app/infra", Field: "password"}

	if Exists(context.Background(), client, spec) {
		t.Error("Exists = true before any value is written, want false")
	}

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "v1"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	if !Exists(context.Background(), client, spec) {
		t.Error("Exists = false after a value is written, want true")
	}
}

// TestRotateRetriesVaultWriteAfterApplySucceeds covers failure point B: Apply already changed
// the live credential to a known value. The Vault write MUST retry rather than surface a bare
// error, after which the stale value would be left stored in Vault.
func TestRotateRetriesVaultWriteAfterApplySucceeds(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	store.failWritesRemaining = 2

	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			return nil
		},
	}

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v, want the retry to absorb the two transient write failures", err)
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != next {
		t.Errorf("stored value = %q, ok=%v, want %q", stored, ok, next)
	}
}

// TestReconcileAppliesVaultStoredValueAsNext covers pushing a value Vault already holds out to
// a drifted live service, given the actual current credential the live service holds.
func TestReconcileAppliesVaultStoredValueAsNext(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "vault-value"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	var gotPrevious, gotNext string
	spec := Spec{
		Mount: "secret",
		Path:  "app/infra",
		Field: "password",
		Deploy: func(ctx context.Context, previous, next string) error {
			gotPrevious, gotNext = previous, next
			return nil
		},
	}

	if err := Reconcile(context.Background(), client, spec, "live-value"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if gotPrevious != "live-value" || gotNext != "vault-value" {
		t.Errorf("Apply(%q, %q), want Apply(%q, %q)", gotPrevious, gotNext, "live-value", "vault-value")
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

	applyCalled := false
	spec := Spec{
		Mount: "secret",
		Path:  "app/infra",
		Field: "password",
		Deploy: func(ctx context.Context, previous, next string) error {
			applyCalled = true
			return nil
		},
	}

	if err := Reconcile(context.Background(), client, spec, "live-value"); err == nil {
		t.Fatal("Reconcile: want error, got nil")
	}
	if applyCalled {
		t.Error("Apply was called with nothing in Vault to push, want it skipped")
	}
}

// TestReconcilePropagatesApplyFailure covers a wrong previous: Reconcile returns the failure
// unchanged rather than guessing at a different previous value.
func TestReconcilePropagatesApplyFailure(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "vault-value"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	spec := Spec{
		Mount: "secret",
		Path:  "app/infra",
		Field: "password",
		Deploy: func(ctx context.Context, previous, next string) error {
			return errAuth
		},
	}

	if err := Reconcile(context.Background(), client, spec, "wrong-previous"); !errors.Is(err, errAuth) {
		t.Errorf("Reconcile: err = %v, want errAuth", err)
	}
}

// seedField writes one field at the fixed test path, failing the test when the write fails.
func seedField(t *testing.T, client *vaultapi.Client, field, value string) {
	t.Helper()
	if err := writeField(context.Background(), client, "secret", "app/infra", field, value); err != nil {
		t.Fatalf("seed %s: %v", field, err)
	}
}

// guessLadderCase is one row of TestReconcileEmptyPreviousGuessLadder. acceptedGuess names the
// single previous value the fake live service accepts, with "" meaning every guess is rejected.
type guessLadderCase struct {
	name            string
	defaultPrevious string
	acceptedGuess   string
	wantAttempts    []string
	wantErr         bool
}

func (c guessLadderCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "vault-value")

	var attempts []string
	spec := Spec{
		Mount:                  "secret",
		Path:                   "app/infra",
		Field:                  "password",
		FactoryDefaultPassword: c.defaultPrevious,
		Deploy: func(ctx context.Context, previous, next string) error {
			attempts = append(attempts, previous)
			if previous == c.acceptedGuess {
				return nil
			}
			return errAuth
		},
	}

	c.assertOutcome(t, Reconcile(context.Background(), client, spec, ""), attempts)
}

func (c guessLadderCase) assertOutcome(t *testing.T, err error, attempts []string) {
	t.Helper()
	switch {
	case c.wantErr && !errors.Is(err, errAuth):
		t.Errorf("Reconcile: err = %v, want errAuth", err)
	case !c.wantErr && err != nil:
		t.Fatalf("Reconcile: %v", err)
	}
	if !slices.Equal(attempts, c.wantAttempts) {
		t.Errorf("attempts = %v, want %v", attempts, c.wantAttempts)
	}
}

// TestReconcileEmptyPreviousGuessLadder covers an operator leaving previous blank: Reconcile
// walks a fixed guess ladder (the Vault value, then Spec.DefaultPrevious) and stops at the
// first guess Apply accepts.
func TestReconcileEmptyPreviousGuessLadder(t *testing.T) {
	cases := []guessLadderCase{
		{
			name:            "vault value accepted on the first attempt",
			defaultPrevious: "admin",
			acceptedGuess:   "vault-value",
			wantAttempts:    []string{"vault-value"},
		},
		{
			name:            "falls back to DefaultPrevious once the vault value is rejected",
			defaultPrevious: "admin",
			acceptedGuess:   "admin",
			wantAttempts:    []string{"vault-value", "admin"},
		},
		{
			name:            "fails once every guess is exhausted with no DefaultPrevious set",
			defaultPrevious: "",
			acceptedGuess:   "",
			wantAttempts:    []string{"vault-value"},
			wantErr:         true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// roundTripCase is one row of TestWriteFieldRoundTripsSpecialCharacters. seed decides which of
// the two writeField branches the case exercises: a seeded path patches, an empty path creates.
type roundTripCase struct {
	name string
	seed bool
	evil string
}

func (c roundTripCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if c.seed {
		seedField(t, client, "seed", "x")
	}
	seedField(t, client, "password", c.evil)

	got, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || got != c.evil {
		t.Errorf("readField = %q, ok=%v, want %q preserved as one opaque value", got, ok, c.evil)
	}
	injected, ok := readField(context.Background(), client, "secret", "app/infra", "injected")
	if ok {
		t.Errorf("sibling field injected=%q appeared, want the crafted value treated as one string", injected)
	}
}

// TestWriteFieldRoundTripsSpecialCharacters covers both write paths writeField selects between:
// WriteWithContext for a path with no document yet, JSONMergePatch for one that already holds a
// document. Either path MUST treat the value as one opaque string, never as extra JSON structure.
func TestWriteFieldRoundTripsSpecialCharacters(t *testing.T) {
	cases := []roundTripCase{
		{"create path, no existing document", false, "\"}}; DROP TABLE secrets; --\n\x00<script>\\"},
		{"patch path, existing document", true, `value","injected":"true`},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestReconcileTreatsStoredEmptyStringAsAValidNext covers a Vault field holding "": a value
// distinct from the field being absent. Reconcile MUST still push that stored empty string out.
func TestReconcileTreatsStoredEmptyStringAsAValidNext(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", ""); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}

	var gotNext string
	called := false
	spec := Spec{
		Mount: "secret",
		Path:  "app/infra",
		Field: "password",
		Deploy: func(ctx context.Context, previous, next string) error {
			called = true
			gotNext = next
			return nil
		},
	}

	if err := Reconcile(context.Background(), client, spec, "live-value"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !called || gotNext != "" {
		t.Errorf("Apply called=%v next=%q, want Apply called once with next empty string", called, gotNext)
	}
}

// TestRotateRecoversWhenApplySucceededButCommitNeverRan covers the worst crash point: a prior
// run staged {previous, pending_next}, the live service accepted the Apply, and the process
// died before the final Vault commit. Rotate MUST detect and commit that already-live value.
func TestRotateRecoversWhenApplySucceededButCommitNeverRan(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()

	if err := writeField(context.Background(), client, "secret", "app/infra", "password", "old-value"); err != nil {
		t.Fatalf("seed writeField: %v", err)
	}
	if err := writeRotationState(context.Background(), client, "secret", "app/infra", "password",
		rotationState{Previous: "old-value", PendingNext: "actually-applied-value"}); err != nil {
		t.Fatalf("seed writeRotationState: %v", err)
	}

	var attempts []string
	spec := Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
		Deploy: func(ctx context.Context, previous, next string) error {
			attempts = append(attempts, previous)
			if previous == "actually-applied-value" {
				return nil
			}
			return errAuth
		},
	}

	next, err := Rotate(context.Background(), client, spec, nil)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if next != "actually-applied-value" {
		t.Errorf("Rotate returned %q, want the recovered pending_next %q instead of a freshly minted value", next, "actually-applied-value")
	}
	stored, ok := readField(context.Background(), client, "secret", "app/infra", "password")
	if !ok || stored != "actually-applied-value" {
		t.Errorf("stored value = %q, ok=%v, want %q committed", stored, ok, "actually-applied-value")
	}
}

// TestRotatePreservesStagedStateWhenTheRecoveryProbeIsInconclusive covers a staged pending value
// and a probe which fails for a transport reason. The failure proves nothing about the live
// service. The staged record MUST survive and Rotate MUST refuse to mint over the record.
func TestRotatePreservesStagedStateWhenTheRecoveryProbeIsInconclusive(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	staged := rotationState{Previous: "old-value", PendingNext: "value-the-service-may-hold"}
	if err := writeRotationState(context.Background(), client, "secret", "app/infra", "password", staged); err != nil {
		t.Fatalf("seed writeRotationState: %v", err)
	}

	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		return errors.New("dial tcp 10.0.0.9:443: connect: connection refused")
	}

	if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
		t.Fatal("Rotate: want an error while the state of the live service stays unknown, got nil")
	}

	_, pending, ok := readStagedRotationFields(t, client, "secret", "app/infra", "password")
	if !ok {
		t.Fatal("the staged rotation record was cleared, want the record preserved for the next run")
	}
	if pending != "value-the-service-may-hold" {
		t.Errorf("staged pending_next = %q, want %q preserved", pending, "value-the-service-may-hold")
	}
}

// lockTestSpec returns the base Spec against which every subtest of TestRotateOwnLockLifecycle
// rotates. The fixed Vault location and secret shape are shared across every subtest.
func lockTestSpec() Spec {
	return Spec{
		Mount:   "secret",
		Path:    "app/infra",
		Field:   "password",
		Length:  16,
		Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
	}
}

// TestRotateOwnLockLifecycle covers the full lifecycle of the advisory lock Rotate stakes on
// itself: a concurrent call arriving while the lock is held MUST be rejected before reaching
// Apply, and a later, non-overlapping call MUST succeed once the lock is released.
func TestRotateOwnLockLifecycle(t *testing.T) {
	t.Run("rejects a concurrent call while the lock is held", testLockRejectsConcurrentCall)
	t.Run("releases the lock after completing", testLockReleasesAfterCompleting)
	t.Run("retries lock acquisition after a transient version conflict", testLockRetriesTransientConflict)
	t.Run("gives up after exhausting every retry against a persistent conflict", testLockGivesUpAfterPersistentConflict)
	t.Run("admits one holder when two callers interleave the check and the acquisition", testLockAdmitsOneInterleavedHolder)
	t.Run("leaves a lock staked by a different holder intact on release", testLockReleaseSpareForeignHolder)
}

// testLockAdmitsOneInterleavedHolder drives the interleaving Rotate itself performs: both callers
// clear checkNotLocked before either one reaches acquireLock. Exactly one caller MUST come away
// holding the lock.
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
	var held rotationLock
	if err := json.Unmarshal([]byte(raw), &held); err != nil {
		t.Fatalf("Unmarshal held lock: %v", err)
	}
	if held.Holder != "other-process" {
		t.Errorf("lock holder = %q, want %q", held.Holder, "other-process")
	}
}

func testLockRejectsConcurrentCall(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	var concurrentErr error
	concurrentApplyCalled := false
	outer := lockTestSpec()
	outer.Deploy = func(ctx context.Context, previous, next string) error {
		inner := lockTestSpec()
		inner.Deploy = func(ctx context.Context, previous, next string) error {
			concurrentApplyCalled = true
			return nil
		}
		_, concurrentErr = Rotate(context.Background(), client, inner, nil)
		return nil
	}

	if _, err := Rotate(context.Background(), client, outer, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if concurrentErr == nil {
		t.Fatal("concurrent Rotate: want error while the first call still held the lock, got nil")
	}
	if concurrentApplyCalled {
		t.Error("concurrent Rotate reached Apply, want it rejected by the lock first")
	}
}

func testLockReleasesAfterCompleting(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error { return nil }

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

	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error { return nil }

	if _, err := Rotate(context.Background(), client, spec, nil); err != nil {
		t.Fatalf("Rotate: %v, want the retry to absorb the transient version conflicts", err)
	}
}

func testLockGivesUpAfterPersistentConflict(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")
	store.failCASConflicts = acquireLockMaxAttempts

	applyCalled := false
	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		applyCalled = true
		return nil
	}

	if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
		t.Fatal("Rotate: want error after exhausting every lock retry, got nil")
	}
	if applyCalled {
		t.Error("Apply was called despite the lock never being acquired")
	}
}

// outsideWriteCase is one row of TestRotateResolvesAgainstAWriterOutsideThisRotation. liveValue
// names the single credential the fake live service accepts, letting each row decide whether the
// value the outside writer stored is genuinely live.
type outsideWriteCase struct {
	name             string
	storedByOutsider string
	liveValue        string
	wantValue        string
	wantErr          bool
}

func (c outsideWriteCase) run(t *testing.T) {
	srv, client, _ := newFakeKVv2Server(t)
	defer srv.Close()
	seedField(t, client, "password", "old-value")

	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error {
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

// TestRotateResolvesAgainstAWriterOutsideThisRotation covers an out-of-band write changing the
// Vault field mid-rotation. Rotate MUST confirm the live service holds the raced-in value before
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
			name: "another rotation holds the lock",
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

			applyCalled := false
			spec := Spec{
				Mount:   "secret",
				Path:    "app/infra",
				Field:   "password",
				Length:  16,
				Classes: []secretgen.CharClass{secretgen.Upper, secretgen.Lower, secretgen.Digit},
				Deploy: func(ctx context.Context, previous, next string) error {
					applyCalled = true
					return nil
				},
			}

			if _, err := Rotate(context.Background(), client, spec, nil); err == nil {
				t.Fatal("Rotate: want error, got nil")
			}
			if applyCalled {
				t.Error("Apply was called, want Rotate to refuse before reaching the live service")
			}
		})
	}
}

// reReadCase is one row of TestRotateReReadsFieldStateAfterAcquiringTheLock. outOfBand is the
// value an outside writer stores at password immediately after the pre-lock read of Rotate
// observes the field as absent.
type reReadCase struct {
	name      string
	outOfBand string
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

	var attempts []string
	spec := lockTestSpec()
	spec.Deploy = func(ctx context.Context, previous, next string) error {
		attempts = append(attempts, previous)
		return nil
	}

	if _, err := Rotate(ctx, client, spec, nil); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if len(attempts) != 1 || attempts[0] != c.outOfBand {
		t.Errorf("Apply attempts = %v, want exactly one call authenticated with %q, the value an outside writer stored after the initial read observed the field as absent", attempts, c.outOfBand)
	}
}

// TestRotateReReadsFieldStateAfterAcquiringTheLock covers a write landing, from outside this
// rotation, between the pre-lock read of Rotate and the point at which Rotate decides whether to
// call Apply. Authentication MUST proceed against the field value held once the lock is staked.
func TestRotateReReadsFieldStateAfterAcquiringTheLock(t *testing.T) {
	cases := []reReadCase{
		{name: "a genuine credential appears out of band", outOfBand: "external-value"},
		{name: "an empty string appears out of band", outOfBand: ""},
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// TestIsCASConflictRequiresTheCASStatusCode covers a false-positive risk in matching against the
// formatted error string alone: the exact check-and-set wording under an unrelated HTTP status
// MUST NOT be classified as a version conflict.
func TestIsCASConflictRequiresTheCASStatusCode(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "400 carrying the real conflict message is a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusBadRequest, Errors: []string{casConflictSubstring}},
			want: true,
		},
		{
			name: "500 echoing the identical wording is not a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusInternalServerError, Errors: []string{casConflictSubstring}},
			want: false,
		},
		{
			name: "400 carrying an unrelated message is not a conflict",
			err:  &vaultapi.ResponseError{StatusCode: http.StatusBadRequest, Errors: []string{"permission denied"}},
			want: false,
		},
		{
			name: "a nil error is not a conflict",
			err:  nil,
			want: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isCASConflict(c.err); got != c.want {
				t.Errorf("isCASConflict(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}
}

// TestWriteFieldPatchesWithoutAnExistenceProbe covers the round trip cost of writeField: updating
// an already-seeded field MUST issue exactly one request, the patch itself, never a leading probe
// read to decide which write form applies.
func TestWriteFieldPatchesWithoutAnExistenceProbe(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	ctx := context.Background()
	seedField(t, client, "password", "old-value")

	before := len(store.requests)
	if err := writeField(ctx, client, "secret", "app/infra", "password", "new-value"); err != nil {
		t.Fatalf("writeField: %v", err)
	}
	issued := store.requests[before:]
	if len(issued) != 1 {
		t.Errorf("requests issued = %v, want exactly one patch and no leading existence probe", issued)
	}

	got, ok := readField(ctx, client, "secret", "app/infra", "password")
	if !ok || got != "new-value" {
		t.Errorf("readField = %q, ok=%v, want %q committed", got, ok, "new-value")
	}
}

// TestWriteFieldCreatesOnFirstWriteAfterAPatchRejection covers the boundary on which the
// probe-free design of writeField depends: a patch against a path holding no document yet MUST
// fall back to a create, at the cost of one rejected patch attempt plus the create itself.
func TestWriteFieldCreatesOnFirstWriteAfterAPatchRejection(t *testing.T) {
	srv, client, store := newFakeKVv2Server(t)
	defer srv.Close()
	ctx := context.Background()

	before := len(store.requests)
	if err := writeField(ctx, client, "secret", "app/infra", "password", "first-value"); err != nil {
		t.Fatalf("writeField: %v", err)
	}
	issued := store.requests[before:]
	if len(issued) != 2 {
		t.Errorf("requests issued = %v, want the rejected patch followed by exactly one create", issued)
	}

	got, ok := readField(ctx, client, "secret", "app/infra", "password")
	if !ok || got != "first-value" {
		t.Errorf("readField = %q, ok=%v, want %q committed", got, ok, "first-value")
	}
}
