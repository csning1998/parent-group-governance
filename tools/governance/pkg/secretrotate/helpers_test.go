package secretrotate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/secretgen"
)

// casConflictBody matches the error text a real Vault server returns for a check-and-set
// mismatch. isCASConflict in the production code matches against this same substring.
const casConflictBody = `{"errors":["check-and-set parameter did not match the current version"]}`

var errAuth = errors.New("auth rejected")

// fakeKVv2 is a minimal in-memory KV-v2 engine at mount "secret" backing an httptest server,
// letting Rotate run end-to-end in tests without a real Vault. everExisted survives a destroy
// call, matching how the real Vault metadata endpoint keeps version history after data is gone.
type fakeKVv2 struct {
	mu                   sync.Mutex
	data                 map[string]map[string]any
	version              map[string]int
	everExisted          map[string]bool
	failWritesRemaining  int
	failPatchesRemaining int
	failCASConflicts     int
	requests             []string
	afterRequest         map[int]func()
}

// fakeVaultPayload is the request body shape shared by the write and patch handlers of the fake server.
// The payload contains the KV v2 data map and an optional check and set version requested by the caller.
type fakeVaultPayload struct {
	Data map[string]any `json:"data"`
	Cas  *int           `json:"cas"`
}

// liveService simulates a target service with a single active password for Spec.Verify and Spec.Deploy.
type liveService struct {
	current   string
	deploys   [][2]string
	verifies  []string
	deployErr error
	verifyErr error
}

func decodeFakeVaultPayload(r *http.Request) (fakeVaultPayload, error) {
	body, _ := io.ReadAll(r.Body)
	var raw struct {
		Data    map[string]any `json:"data"`
		Options struct {
			Cas *int `json:"cas"`
		} `json:"options"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return fakeVaultPayload{}, err
	}
	return fakeVaultPayload{Data: raw.Data, Cas: raw.Options.Cas}, nil
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

func newFakeKVv2Server(t *testing.T) (*httptest.Server, *vaultapi.Client, *fakeKVv2) {
	t.Helper()
	store := &fakeKVv2{
		data:        map[string]map[string]any{},
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

// readStagedRotationFields reads the Write-Ahead staging record Rotate is expected to persist
// at "<field>_rotation" before calling Apply. The record MUST be a JSON string, because a
// consumer such as the ephemeral vault_kv_secret_v2 of Terraform reads every field as a string.
func readStagedRotationFields(t *testing.T, client *vaultapi.Client, mount, path, field string) (previous, pendingNext string, ok bool) {
	t.Helper()
	secret, err := client.Logical().ReadWithContext(context.Background(), mount+"/data/"+path)
	if err != nil || secret == nil {
		return "", "", false
	}
	data, _ := secret.Data["data"].(map[string]any)
	value, present := data[field+"_rotation"]
	if !present || value == nil {
		return "", "", false
	}
	raw, isString := value.(string)
	if !isString {
		t.Fatalf("%s_rotation contains %T, want a JSON string", field, value)
	}
	var staging struct {
		Previous    string `json:"previous"`
		PendingNext string `json:"pending_next"`
	}
	if err := json.Unmarshal([]byte(raw), &staging); err != nil {
		t.Fatalf("%s_rotation is not JSON: %v", field, err)
	}
	return staging.Previous, staging.PendingNext, true
}

// seedField writes one field at the fixed test path. A failed write fails the test.
func seedField(t *testing.T, client *vaultapi.Client, field, value string) {
	t.Helper()
	if err := writeField(context.Background(), client, "secret", "app/infra", field, value); err != nil {
		t.Fatalf("seed %s: %v", field, err)
	}
}

func trimFakeVaultPrefix(path, prefix string) (string, bool) {
	if len(path) < len(prefix) || path[:len(prefix)] != prefix {
		return "", false
	}
	return path[len(prefix):], true
}

// destroy removes the current data at path while leaving everExisted set, simulating `vault kv
// delete` / `vault kv destroy` against a path this package never touched directly.
func (s *fakeKVv2) destroy(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, path)
}

// failNextPatches makes the next n PATCH requests fail with HTTP 500 before any merge is applied.
func (s *fakeKVv2) failNextPatches(n int) {
	s.mu.Lock()
	s.failPatchesRemaining = n
	s.mu.Unlock()
}

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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{
			"data":     fields,
			"metadata": map[string]any{"version": s.version[path]},
		},
	})
}

// handleMetadata answers the Vault metadata endpoint: current_version remains positive once a
// path has ever contained data, even after destroy deletes the data itself.
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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"data": map[string]any{"current_version": s.version[path]},
	})
}

// handlePatch applies an RFC 7396 JSON merge patch to the "data" object to preserve unmodified sibling fields.
func (s *fakeKVv2) handlePatch(w http.ResponseWriter, r *http.Request, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failPatchesRemaining > 0 {
		s.failPatchesRemaining--
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
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
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
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
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{}})
}

// recordRequest appends one "METHOD path" entry to the request log. The hook staged for the position of
// the new entry (counted from 1) fires after mu is released. The hook can therefore issue its own requests
// against the same server without self deadlock.
func (s *fakeKVv2) recordRequest(method, path string) {
	s.mu.Lock()
	s.requests = append(s.requests, method+" "+path)
	hook := s.afterRequest[len(s.requests)]
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// rejectCAS reports whether the write MUST be rejected as a check-and-set conflict: either a
// forced conflict staged by a test through failCASConflicts, or a version mismatch against the
// requested cas value. rejectCAS assumes the caller has already locked s.mu.
func (s *fakeKVv2) rejectCAS(path string, cas *int) bool {
	if s.failCASConflicts > 0 {
		s.failCASConflicts--
		return true
	}
	return cas != nil && *cas != s.version[path]
}

func (s *liveService) bind(spec Spec) Spec {
	spec.Deploy = s.deploy
	spec.Verify = s.verify
	return spec
}

func (s *liveService) deploy(ctx context.Context, previous, next string) error {
	s.deploys = append(s.deploys, [2]string{previous, next})
	if s.deployErr != nil {
		return s.deployErr
	}
	if previous != s.current {
		return fmt.Errorf("%w: test", ErrAuthRejected)
	}
	s.current = next
	return nil
}

func (s *liveService) verify(ctx context.Context, secret string) (bool, error) {
	s.verifies = append(s.verifies, secret)
	if s.verifyErr != nil {
		return false, s.verifyErr
	}
	return secret == s.current, nil
}
