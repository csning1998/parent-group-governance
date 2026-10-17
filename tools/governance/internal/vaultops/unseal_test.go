package vaultops

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

// newFakeUnsealServer records submitted unseal keys and fails requests at or after failOnKeyIndex.
func newFakeUnsealServer(t *testing.T, failOnKeyIndex int) (*httptest.Server, *[]string) {
	t.Helper()
	received := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/sys/seal-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sealed": true})
	})
	mux.HandleFunc("/v1/sys/unseal", func(w http.ResponseWriter, r *http.Request) {
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
		_ = json.NewEncoder(w).Encode(map[string]any{"sealed": false})
	})
	srv := httptest.NewServer(mux)
	return srv, received
}

// TestUnsealParsesLineByLine covers blank-line skipping, a blank-only file, and CRLF line trimming.
func TestUnsealParsesLineByLine(t *testing.T) {
	cases := []struct {
		name         string
		keysRaw      string
		wantReceived []string
	}{
		{"skips blank lines", "\n\n   \nkey-one\n\nkey-two\n", []string{"key-one", "key-two"}},
		{"blank-only file does not submit a key", "\n\n  \n", nil},
		{"trims CRLF line endings", "key-one\r\nkey-two\r\n", []string{"key-one", "key-two"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, received := newFakeUnsealServer(t, -1)
			defer srv.Close()
			p := prepareTestPaths(t)
			if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p.UnsealKeyFile(), []byte(c.keysRaw), 0o600); err != nil {
				t.Fatal(err)
			}
			op := newTestOperator(t, p, srv.URL)

			_ = op.Unseal(context.Background())
			if !slices.Equal(*received, c.wantReceived) {
				t.Errorf("received = %v, want %v", *received, c.wantReceived)
			}
		})
	}
}

// TestUnsealStopsAtFirstFailure verifies that remaining unseal keys MUST NOT be submitted after an API failure.
func TestUnsealStopsAtFirstFailure(t *testing.T) {
	srv, received := newFakeUnsealServer(t, 1)
	defer srv.Close()
	p := prepareTestPaths(t)
	if err := os.MkdirAll(p.KeysDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.UnsealKeyFile(), []byte("key-one\nkey-two\nkey-three\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	op := newTestOperator(t, p, srv.URL)

	err := op.Unseal(context.Background())
	if err == nil {
		t.Fatal("Unseal: want error, got nil")
	}
	if !slices.Equal(*received, []string{"key-one", "key-two"}) {
		t.Errorf("received = %v, want submission to stop at the failing key without sending key-three", *received)
	}
}
