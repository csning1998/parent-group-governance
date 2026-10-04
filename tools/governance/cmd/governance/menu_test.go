package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

const (
	labelUnseal        = "[Vault] Unseal Bastion Vault"
	labelTenantSession = "[Vault] Open Tenant Operator Session"
)

func TestBuildMenuOptions_OffersTenantSessionAfterUnseal(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	options := a.buildMenuOptions()

	labels := make([]string, len(options))
	for i, opt := range options {
		labels[i] = opt.label
	}
	unseal := slices.Index(labels, labelUnseal)
	session := slices.Index(labels, labelTenantSession)
	if unseal < 0 || session != unseal+1 {
		t.Fatalf("menu labels = %q, want %q right after %q", labels, labelTenantSession, labelUnseal)
	}
	if options[session].run == nil {
		t.Errorf("%q has no action", labelTenantSession)
	}
	if last := options[len(options)-1]; last.label != "Quit" || last.run != nil {
		t.Errorf("last menu option = %q, want Quit without an action", last.label)
	}
}

// newMenuApp returns an app whose Bastion Vault is a TLS test server answering the tenant role LIST with roles.
// A nil roles answers 404, as Vault does for a mount without roles.
func newMenuApp(t *testing.T, roles []string, input string) (*app, *bytes.Buffer) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/auth/approle/role" || roles == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"errors":[]}`))
			return
		}
		// An encode failure on the test server surfaces as a parse error at the client under test.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": map[string]interface{}{"keys": roles}})
	}))
	t.Cleanup(srv.Close)

	root, home := t.TempDir(), t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	writeTestFile(t, filepath.Join(root, "vault", "tls", "ca.pem"), caPEM)
	writeTestFile(t, filepath.Join(home, ".vault-token"), []byte("s.admin"))

	var buf bytes.Buffer
	return &app{
		root:             root,
		home:             home,
		bastionVaultAddr: srv.URL,
		out:              ui.New(&buf, &buf),
		in:               bufio.NewReader(strings.NewReader(input)),
	}, &buf
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestRunTenantSessionMenu_StopsWithoutOpeningASession(t *testing.T) {
	tests := []struct {
		name       string
		roles      []string
		input      string
		wantOutput string
	}{
		{name: "no tenant role", roles: nil, input: "", wantOutput: "No tenant Terraform operator role exists"},
		{name: "invalid selection", roles: []string{"meta-platform-terraform-operator"}, input: "9\n", wantOutput: msgInvalidOption},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, buf := newMenuApp(t, tt.roles, tt.input)
			if err := a.runTenantSessionMenu(context.Background()); err != nil {
				t.Fatalf("runTenantSessionMenu: %v", err)
			}
			if !strings.Contains(buf.String(), tt.wantOutput) {
				t.Errorf("output = %q, want %q", buf.String(), tt.wantOutput)
			}
			if strings.Contains(buf.String(), "Tenant session for") {
				t.Errorf("output = %q, want no opened session", buf.String())
			}
		})
	}
}

func TestRunTenantSessionMenu_RequiresTheOperatorToken(t *testing.T) {
	a := &app{root: t.TempDir(), home: t.TempDir(), out: ui.New(io.Discard, io.Discard)}

	err := a.runTenantSessionMenu(context.Background())
	if err == nil || !strings.Contains(err.Error(), "root token not found") {
		t.Errorf("runTenantSessionMenu error = %v, want the missing root token", err)
	}
}
