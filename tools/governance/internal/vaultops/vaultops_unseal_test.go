package vaultops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	vaultapi "github.com/hashicorp/vault/api"
)

// newFakeUnsealServer records every key submitted to /v1/sys/unseal, in order. failOnKeyIndex,
// when non-negative, fails the submission at that zero-based position and every later request.
func newFakeUnsealServer(t *testing.T, failOnKeyIndex int) (*httptest.Server, *[]string) {
	t.Helper()
	received := &[]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Key string `json:"key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		*received = append(*received, body.Key)
		if failOnKeyIndex >= 0 && len(*received)-1 >= failOnKeyIndex {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"sealed": false})
	}))
	return srv, received
}

func newUnsealTestClient(t *testing.T, addr string) *vaultapi.Client {
	t.Helper()
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	client.SetMaxRetries(0)
	return client
}

// TestApplyUnsealKeysParsesLineByLine covers blank-line skipping, a blank-only file submitting
// nothing, and CRLF line endings not leaking into a submitted key.
func TestApplyUnsealKeysParsesLineByLine(t *testing.T) {
	cases := []struct {
		name         string
		keysRaw      string
		wantReceived []string
	}{
		{"skips blank lines", "\n\n   \nkey-one\n\nkey-two\n", []string{"key-one", "key-two"}},
		{"blank-only file submits nothing", "\n\n  \n", nil},
		{"trims CRLF line endings", "key-one\r\nkey-two\r\n", []string{"key-one", "key-two"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, received := newFakeUnsealServer(t, -1)
			defer srv.Close()
			client := newUnsealTestClient(t, srv.URL)

			if err := applyUnsealKeys(context.Background(), client, []byte(c.keysRaw)); err != nil {
				t.Fatalf("applyUnsealKeys: %v", err)
			}
			if !slices.Equal(*received, c.wantReceived) {
				t.Errorf("received = %v, want %v", *received, c.wantReceived)
			}
		})
	}
}

// TestApplyUnsealKeysStopsAtFirstFailure covers a rejected key partway through the file: no key
// after the failing one MUST be submitted.
func TestApplyUnsealKeysStopsAtFirstFailure(t *testing.T) {
	srv, received := newFakeUnsealServer(t, 1)
	defer srv.Close()
	client := newUnsealTestClient(t, srv.URL)

	err := applyUnsealKeys(context.Background(), client, []byte("key-one\nkey-two\nkey-three\n"))
	if err == nil {
		t.Fatal("applyUnsealKeys: want error, got nil")
	}
	if !slices.Equal(*received, []string{"key-one", "key-two"}) {
		t.Errorf("received = %v, want submission to stop at the failing key, key-three never sent", *received)
	}
}
