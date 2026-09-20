package vaultclient_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/pkg/vaultclient"
)

type mockJWTResponse struct {
	statusCode  int
	clientToken string
	errors      []string
}

func matchAuthRoute(r *http.Request, path string) bool {
	isAllowedMethod := r.Method == http.MethodPut || r.Method == http.MethodPost
	return isAllowedMethod && r.URL.Path == path
}

func matchAuthPayload(payload map[string]interface{}, wantRole, wantJWT string) bool {
	if wantRole != "" && payload["role"] != wantRole {
		return false
	}
	if wantJWT != "" && payload["jwt"] != wantJWT {
		return false
	}
	return true
}

func writeJWTResponse(w http.ResponseWriter, resp mockJWTResponse) {
	w.Header().Set("Content-Type", "application/json")
	if resp.statusCode != 0 {
		w.WriteHeader(resp.statusCode)
	}
	if len(resp.errors) > 0 {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"errors": resp.errors})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth": map[string]interface{}{
			"client_token": resp.clientToken,
		},
	})
}

func newMockJWTServer(t *testing.T, mount, wantRole, wantJWT string, resp mockJWTResponse) *vaultclient.Config {
	t.Helper()
	if mount == "" {
		mount = "jwt"
	}
	expectedPath := "/v1/auth/" + mount + "/login"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !matchAuthRoute(r, expectedPath) {
			http.NotFound(w, r)
			return
		}
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !matchAuthPayload(payload, wantRole, wantJWT) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		writeJWTResponse(w, resp)
	}))
	t.Cleanup(server.Close)
	return &vaultclient.Config{Address: server.URL}
}

// TestJWTAuth_SuccessScenarios covers successful token exchange across various trust domains and mount paths.
func TestJWTAuth_SuccessScenarios(t *testing.T) {
	tests := []struct {
		name        string
		mount       string
		role        string
		jwt         string
		clientToken string
	}{
		{
			name:        "default mount path",
			mount:       "",
			role:        "ci-role",
			jwt:         "valid-default-jwt",
			clientToken: "vault-token-default",
		},
		{
			name:        "custom gitlab-saas-jwt mount path",
			mount:       "gitlab-saas-jwt",
			role:        "gitlab-ci-role",
			jwt:         "valid-gitlab-ci-jwt",
			clientToken: "vault-token-gitlab",
		},
		{
			name:        "custom spire-oidc-jwt mount path",
			mount:       "spire-oidc-jwt",
			role:        "spire-workload-role",
			jwt:         "valid-spire-svid",
			clientToken: "vault-token-spire",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newMockJWTServer(t, tc.mount, tc.role, tc.jwt, mockJWTResponse{
				clientToken: tc.clientToken,
			})
			client, err := vaultclient.NewClient(*cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			auth := vaultclient.JWTAuth{
				Token: tc.jwt,
				Role:  tc.role,
				Mount: tc.mount,
			}

			token, err := auth.Login(context.Background(), client)
			if err != nil {
				t.Fatalf("Login() error = %v", err)
			}
			if token != tc.clientToken {
				t.Errorf("Login() token = %q, want %q", token, tc.clientToken)
			}
		})
	}
}

// TestJWTAuth_ClientInputValidation covers rejection of invalid client configurations prior to issuing network requests.
func TestJWTAuth_ClientInputValidation(t *testing.T) {
	validClient, err := vaultclient.NewClient(vaultclient.Config{Address: "http://127.0.0.1:8200"})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}

	tests := []struct {
		name      string
		auth      vaultclient.JWTAuth
		useNilCli bool
		wantErr   bool
	}{
		{
			name: "missing jwt token",
			auth: vaultclient.JWTAuth{
				Token: "",
				Role:  "valid-role",
			},
			wantErr: true,
		},
		{
			name: "missing role name",
			auth: vaultclient.JWTAuth{
				Token: "valid-jwt",
				Role:  "",
			},
			wantErr: true,
		},
		{
			name: "both token and role missing",
			auth: vaultclient.JWTAuth{
				Token: "",
				Role:  "",
			},
			wantErr: true,
		},
		{
			name: "nil vault client instance",
			auth: vaultclient.JWTAuth{
				Token: "valid-jwt",
				Role:  "valid-role",
			},
			useNilCli: true,
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clientTarget := validClient
			if tc.useNilCli {
				clientTarget = nil
			}

			_, err := tc.auth.Login(context.Background(), clientTarget)
			if (err != nil) != tc.wantErr {
				t.Errorf("Login(%s) error = %v, wantErr = %v", tc.name, err, tc.wantErr)
			}
		})
	}
}

// TestJWTAuth_ServerErrorScenarios covers HTTP status codes and error responses from the Vault backend.
func TestJWTAuth_ServerErrorScenarios(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		errors     []string
	}{
		{
			name:       "400 claim verification failure",
			statusCode: http.StatusBadRequest,
			errors:     []string{"claim verification failed"},
		},
		{
			name:       "401 unauthorized credentials",
			statusCode: http.StatusUnauthorized,
			errors:     []string{"invalid token or role"},
		},
		{
			name:       "500 internal vault error",
			statusCode: http.StatusInternalServerError,
			errors:     []string{"internal backend error"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := newMockJWTServer(t, "jwt", "", "", mockJWTResponse{
				statusCode: tc.statusCode,
				errors:     tc.errors,
			})
			client, err := vaultclient.NewClient(*cfg)
			if err != nil {
				t.Fatalf("NewClient: %v", err)
			}

			auth := vaultclient.JWTAuth{
				Token: "some-jwt",
				Role:  "some-role",
			}

			_, err = auth.Login(context.Background(), client)
			if err == nil {
				t.Fatalf("Login(%s) expected error, got nil", tc.name)
			}
		})
	}
}
