package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

func newMockAppRoleServer(t *testing.T, mount, wantRoleID, wantSecretID string, resp mockJWTResponse) *vaultclient.Config {
	t.Helper()
	expectedPath := "/v1/auth/" + mount + "/login"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !matchAuthRoute(r, expectedPath) {
			http.NotFound(w, r)
			return
		}
		var payload map[string]any
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload["role_id"] != wantRoleID || payload["secret_id"] != wantSecretID {
			http.Error(w, "invalid role or secret ID", http.StatusBadRequest)
			return
		}
		writeJWTResponse(w, resp)
	}))
	t.Cleanup(server.Close)
	return &vaultclient.Config{Address: server.URL}
}

// TestAppRoleAuth_SuccessScenarios covers token exchange on the default and on a custom mount path.
func TestAppRoleAuth_SuccessScenarios(t *testing.T) {
	tests := []struct {
		name       string
		mount      string
		wantMount  string
		roleID     string
		secretID   string
		wantClient string
	}{
		{name: "default mount path", mount: "", wantMount: "approle", roleID: "role-a", secretID: "secret-a", wantClient: "s.tenant-a"},
		{name: "custom mount path", mount: "approle-tenants", wantMount: "approle-tenants", roleID: "role-b", secretID: "secret-b", wantClient: "s.tenant-b"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newMockAppRoleServer(t, tc.wantMount, tc.roleID, tc.secretID, mockJWTResponse{clientToken: tc.wantClient})
			client, err := vaultclient.NewClient(*cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			auth := vaultclient.AppRoleAuth{Mount: tc.mount, RoleID: tc.roleID, SecretID: tc.secretID}
			token, err := auth.Login(context.Background(), client)
			if err != nil {
				t.Fatalf("Login() error = %v", err)
			}
			if token != tc.wantClient {
				t.Errorf("Login() token = %q, want %q", token, tc.wantClient)
			}
		})
	}
}

// TestAppRoleAuth_ClientInputValidation covers rejection of invalid inputs prior to issuing network requests.
func TestAppRoleAuth_ClientInputValidation(t *testing.T) {
	validClient, err := vaultclient.NewClient(vaultclient.Config{Address: "http://127.0.0.1:8200"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tests := []struct {
		name      string
		auth      vaultclient.AppRoleAuth
		useNilCli bool
		wantErr   string
	}{
		{name: "missing role ID", auth: vaultclient.AppRoleAuth{SecretID: "secret"}, wantErr: "vaultclient: empty role id provided"},
		{name: "missing secret ID", auth: vaultclient.AppRoleAuth{RoleID: "role"}, wantErr: "vaultclient: empty secret id provided"},
		{name: "nil vault client instance", auth: vaultclient.AppRoleAuth{RoleID: "role", SecretID: "secret"}, useNilCli: true, wantErr: "vaultclient: nil client provided"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientTarget := validClient
			if tc.useNilCli {
				clientTarget = nil
			}

			_, err := tc.auth.Login(context.Background(), clientTarget)
			if err == nil || err.Error() != tc.wantErr {
				t.Errorf("Login(%s) error = %v, want %q", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestAppRoleAuth_ServerErrorScenarios covers error responses and an auth block which lacks a client token.
func TestAppRoleAuth_ServerErrorScenarios(t *testing.T) {
	tests := []struct {
		name string
		resp mockJWTResponse
	}{
		{name: "400 invalid secret ID", resp: mockJWTResponse{statusCode: http.StatusBadRequest, errors: []string{"invalid role or secret ID"}}},
		{name: "403 bound CIDR mismatch", resp: mockJWTResponse{statusCode: http.StatusForbidden, errors: []string{"source address unauthorized"}}},
		{name: "empty client token", resp: mockJWTResponse{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newMockAppRoleServer(t, "approle", "role", "secret", tc.resp)
			client, err := vaultclient.NewClient(*cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			auth := vaultclient.AppRoleAuth{RoleID: "role", SecretID: "secret"}
			if _, err := auth.Login(context.Background(), client); err == nil {
				t.Fatalf("Login(%s) expected error, got nil", tc.name)
			}
		})
	}
}
