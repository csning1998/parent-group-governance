package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

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

func TestInspectStatusDoesNotRetryServerErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	vaultclient.InspectStatus(context.Background(), vaultclient.Config{Address: server.URL})
	if got := requests.Load(); got != 1 {
		t.Errorf("InspectStatus issued %d requests, want 1", got)
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

func TestInspectStatusReturnsBeforeDefaultClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(hangUntilCanceled))
	t.Cleanup(server.Close)

	start := time.Now()
	status := vaultclient.InspectStatus(context.Background(), vaultclient.Config{Address: server.URL})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("InspectStatus took %v against a hung server, want under 5s", elapsed)
	}
	if status.Reachable {
		t.Error("InspectStatus Reachable = true against a hung server, want false")
	}
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

func TestProbeStateLeavesCallerClientRetriesUnchanged(t *testing.T) {
	server := httptest.NewServer(sealStatusJSON(true, false))
	t.Cleanup(server.Close)
	client, err := vaultclient.NewClient(vaultclient.Config{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	wantRetries := client.MaxRetries()

	if _, _, err := vaultclient.ProbeState(context.Background(), client); err != nil {
		t.Fatalf("ProbeState: %v", err)
	}
	if got := client.MaxRetries(); got != wantRetries {
		t.Errorf("caller client MaxRetries = %d after ProbeState, want %d", got, wantRetries)
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

func TestProbeStateReturnsBeforeDefaultClientTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(hangUntilCanceled))
	t.Cleanup(server.Close)
	client, err := vaultclient.NewClient(vaultclient.Config{Address: server.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	start := time.Now()
	running, _, err := vaultclient.ProbeState(context.Background(), client)
	if err != nil {
		t.Fatalf("ProbeState: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("ProbeState took %v against a hung server, want under 5s", elapsed)
	}
	if running {
		t.Error("ProbeState running = true against a hung server, want false")
	}
}

func TestProbeStateSealed(t *testing.T) {
	assertProbeState(t, true, true)
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

func TestProbeStateUnsealed(t *testing.T) {
	assertProbeState(t, false, false)
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

// hangUntilCanceled holds every request open until the client gives up.
func hangUntilCanceled(w http.ResponseWriter, r *http.Request) {
	select {
	case <-r.Context().Done():
	case <-time.After(30 * time.Second):
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
