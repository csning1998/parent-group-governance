package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

type fakeEnv struct {
	mu sync.Mutex
	m  map[string]string
}

func (f *fakeEnv) Set(k, v string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = make(map[string]string)
	}
	f.m[k] = v
}

func (f *fakeEnv) get(k string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[k]
}

func TestNewClient_InvalidTLSConfig(t *testing.T) {
	cfg := vaultclient.Config{
		Address:    "https://127.0.0.1:8200",
		CACertPath: "/nonexistent/path/ca.pem",
	}
	_, err := vaultclient.NewClient(cfg)
	if err == nil {
		t.Fatal("expected error for nonexistent CACertPath, got nil")
	}
}

func TestNewClient_ValidConfig(t *testing.T) {
	cfg := vaultclient.Config{
		Address: "http://127.0.0.1:8200",
		Token:   "s.testtoken",
	}
	client, err := vaultclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error creating client: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Token() != "s.testtoken" {
		t.Fatalf("expected token 's.testtoken', got %q", client.Token())
	}
}

func rejectAllRequests(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "server error", http.StatusInternalServerError)
}

func sealStatusJSON(initialized, sealed bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/seal-status" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"initialized": initialized,
			"sealed":      sealed,
		})
	}
}

func TestInspectStatus(t *testing.T) {
	tests := []struct {
		name             string
		handler          http.HandlerFunc
		closeBeforeQuery bool
		wantReach        bool
		wantInit         bool
		wantSealed       bool
	}{
		{
			name:       "unsealed and initialized",
			handler:    sealStatusJSON(true, false),
			wantReach:  true,
			wantInit:   true,
			wantSealed: false,
		},
		{
			name:       "sealed and initialized",
			handler:    sealStatusJSON(true, true),
			wantReach:  true,
			wantInit:   true,
			wantSealed: true,
		},
		{
			name:             "unreachable",
			handler:          rejectAllRequests,
			closeBeforeQuery: true,
			wantReach:        false,
			wantInit:         false,
			wantSealed:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertInspectStatus(t, tc.handler, tc.closeBeforeQuery, tc.wantReach, tc.wantInit, tc.wantSealed)
		})
	}
}

func assertInspectStatus(t *testing.T, handler http.HandlerFunc, closeBeforeQuery, wantReach, wantInit, wantSealed bool) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	targetAddr := server.URL
	if closeBeforeQuery {
		server.Close()
	}

	status := vaultclient.InspectStatus(context.Background(), vaultclient.Config{Address: targetAddr})
	if status.Reachable != wantReach {
		t.Errorf("Reachable = %v, want %v", status.Reachable, wantReach)
	}
	if status.Initialized != wantInit {
		t.Errorf("Initialized = %v, want %v", status.Initialized, wantInit)
	}
	if status.Sealed != wantSealed {
		t.Errorf("Sealed = %v, want %v", status.Sealed, wantSealed)
	}
}

func TestInspectStatusInvalidTLSReturnsZero(t *testing.T) {
	status := vaultclient.InspectStatus(context.Background(), vaultclient.Config{
		Address:    "https://127.0.0.1:8200",
		CACertPath: "/nonexistent/path/ca.pem",
	})
	if status != (vaultclient.SealStatus{}) {
		t.Errorf("InspectStatus invalid TLS = %+v, want zero value", status)
	}
}

func TestProbeStateNilClient(t *testing.T) {
	running, sealed, err := vaultclient.ProbeState(context.Background(), nil)
	if err == nil {
		t.Fatal("ProbeState(nil): want error, got nil")
	}
	if running || sealed {
		t.Errorf("ProbeState(nil) = (%v, %v), want (false, false)", running, sealed)
	}
}

func TestProbeStateUnreachableReturnsNotRunning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(rejectAllRequests))
	server.Close()
	client, err := vaultclient.NewClient(vaultclient.Config{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	running, sealed, err := vaultclient.ProbeState(context.Background(), client)
	if err != nil {
		t.Fatalf("ProbeState unreachable: %v", err)
	}
	if running || sealed {
		t.Errorf("ProbeState unreachable = (%v, %v), want (false, false)", running, sealed)
	}
}

func TestProbeStateSealed(t *testing.T) {
	assertProbeState(t, true, true)
}

func TestProbeStateUnsealed(t *testing.T) {
	assertProbeState(t, false, false)
}

func assertProbeState(t *testing.T, handlerSealed, wantSealed bool) {
	t.Helper()
	server := httptest.NewServer(sealStatusJSON(true, handlerSealed))
	t.Cleanup(server.Close)
	client, err := vaultclient.NewClient(vaultclient.Config{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	running, sealed, err := vaultclient.ProbeState(context.Background(), client)
	if err != nil {
		t.Fatalf("ProbeState: %v", err)
	}
	if !running {
		t.Fatal("ProbeState running = false, want true")
	}
	if sealed != wantSealed {
		t.Errorf("ProbeState sealed = %v, want %v", sealed, wantSealed)
	}
}
