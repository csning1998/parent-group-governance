package vaultops

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOpenTenantSession_ReturnsTenantSession(t *testing.T) {
	_, srv := newFakeTenantVault(t, "approle")
	admin := newFakeAdminClient(t, srv.URL)

	got, err := OpenTenantSession(context.Background(), admin, TenantSessionRequest{Tenant: "meta-platform"})
	if err != nil {
		t.Fatalf("OpenTenantSession: %v", err)
	}
	want := TenantSession{Token: fakeTenantToken, Accessor: fakeTenantAccess}
	if got != want {
		t.Errorf("OpenTenantSession = %+v, want %+v", got, want)
	}
}

// TestOpenTenantSession_SendsEachTokenOnlyToItsEndpoint pins the token boundary: the operator token mints, the
// wrapping token unwraps, and the login carries neither the operator token nor the ambient VAULT_TOKEN.
func TestOpenTenantSession_SendsEachTokenOnlyToItsEndpoint(t *testing.T) {
	fv, srv := newFakeTenantVault(t, "approle")
	admin := newFakeAdminClient(t, srv.URL)

	if _, err := OpenTenantSession(context.Background(), admin, TenantSessionRequest{Tenant: "meta-platform"}); err != nil {
		t.Fatalf("OpenTenantSession: %v", err)
	}

	tests := []struct {
		endpoint  string
		wantToken string
	}{
		{endpoint: "/role/" + fakeOperatorRole + "/role-id", wantToken: fakeAdminToken},
		{endpoint: "/role/" + fakeOperatorRole + "/secret-id", wantToken: fakeAdminToken},
		{endpoint: "/sys/wrapping/unwrap", wantToken: fakeWrappingToken},
		{endpoint: "/auth/approle/login", wantToken: ""},
	}
	calls := fv.snapshot()
	for _, tt := range tests {
		t.Run(tt.endpoint, func(t *testing.T) {
			c, ok := findTenantCall(calls, tt.endpoint)
			if !ok {
				t.Fatalf("no request to %s, got %d requests", tt.endpoint, len(calls))
			}
			if c.token != tt.wantToken {
				t.Errorf("X-Vault-Token on %s = %q, want %q", tt.endpoint, c.token, tt.wantToken)
			}
		})
	}
}

func TestOpenTenantSession_RequestsSingleUseWrappedSecretID(t *testing.T) {
	tests := []struct {
		name    string
		req     TenantSessionRequest
		mount   string
		wantTTL string
	}{
		{name: "defaults", req: TenantSessionRequest{Tenant: "meta-platform"}, mount: "approle", wantTTL: "60s"},
		{name: "explicit", req: TenantSessionRequest{Tenant: "meta-platform", Mount: "approle-tenants", WrapTTL: 30 * time.Second}, mount: "approle-tenants", wantTTL: "30s"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv, srv := newFakeTenantVault(t, tt.mount)
			admin := newFakeAdminClient(t, srv.URL)

			if _, err := OpenTenantSession(context.Background(), admin, tt.req); err != nil {
				t.Fatalf("OpenTenantSession: %v", err)
			}
			assertSingleUseWrap(t, fv.snapshot(), tt.wantTTL)
		})
	}
}

func assertSingleUseWrap(t *testing.T, calls []tenantCall, wantTTL string) {
	t.Helper()
	c, ok := findTenantCall(calls, "/secret-id")
	if !ok {
		t.Fatal("no secret-id request")
	}
	if c.wrapTTL != wantTTL {
		t.Errorf("X-Vault-Wrap-TTL = %q, want %q", c.wrapTTL, wantTTL)
	}
	if c.body["num_uses"] != float64(1) {
		t.Errorf("num_uses = %v, want 1", c.body["num_uses"])
	}
	if c.body["ttl"] != wantTTL {
		t.Errorf("ttl = %v, want %q", c.body["ttl"], wantTTL)
	}
}

func TestOpenTenantSession_FailsClosedWhenWrapIsConsumed(t *testing.T) {
	fv, srv := newFakeTenantVault(t, "approle")
	fv.injectFault("/sys/wrapping/unwrap", http.StatusBadRequest)
	admin := newFakeAdminClient(t, srv.URL)

	_, err := OpenTenantSession(context.Background(), admin, TenantSessionRequest{Tenant: "meta-platform"})
	if !errors.Is(err, ErrWrapConsumed) {
		t.Fatalf("OpenTenantSession error = %v, want ErrWrapConsumed", err)
	}
	if _, ok := findTenantCall(fv.snapshot(), "/login"); ok {
		t.Error("OpenTenantSession sent a login after the unwrap failed")
	}
}

func TestOpenTenantSession_RejectsInvalidTenant(t *testing.T) {
	for _, tenant := range []string{"", "Meta-Platform", "meta platform", "meta/platform", "../meta", "meta-platform-"} {
		t.Run(tenant, func(t *testing.T) {
			fv, srv := newFakeTenantVault(t, "approle")
			admin := newFakeAdminClient(t, srv.URL)

			_, err := OpenTenantSession(context.Background(), admin, TenantSessionRequest{Tenant: tenant})
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("OpenTenantSession(%q) error = %v, want ErrInvalidTenant", tenant, err)
			}
			if n := len(fv.snapshot()); n != 0 {
				t.Errorf("OpenTenantSession(%q) sent %d requests, want 0", tenant, n)
			}
		})
	}
}

// TestOpenTenantSession_FailsOnVaultFaults covers each Vault answer which MUST stop the session before the caller
// receives a token, and the revoke of a token whose lookup fails.
func TestOpenTenantSession_FailsOnVaultFaults(t *testing.T) {
	tests := []struct {
		name       string
		inject     func(*fakeTenantVault)
		wantErr    string
		wantRevoke bool
	}{
		{name: "role id denied", inject: func(f *fakeTenantVault) { f.injectFault("/role-id", http.StatusForbidden) }, wantErr: "vaultops: read role id"},
		{name: "role id absent", inject: func(f *fakeTenantVault) { f.injectEmptyData("/role-id") }, wantErr: "vaultops: role_id missing"},
		{name: "mint denied", inject: func(f *fakeTenantVault) { f.injectFault("/secret-id", http.StatusForbidden) }, wantErr: "vaultops: mint secret id"},
		{name: "mint unwrapped", inject: func(f *fakeTenantVault) { f.unwrappedMint = true }, wantErr: "returned without response wrapping"},
		{name: "unwrap unavailable", inject: func(f *fakeTenantVault) { f.injectFault("/sys/wrapping/unwrap", http.StatusInternalServerError) }, wantErr: "vaultops: unwrap secret id"},
		{name: "secret id absent", inject: func(f *fakeTenantVault) { f.injectEmptyData("/sys/wrapping/unwrap") }, wantErr: "vaultops: secret_id missing"},
		{name: "login rejected", inject: func(f *fakeTenantVault) { f.injectFault("/login", http.StatusBadRequest) }, wantErr: "vaultops: tenant login"},
		{name: "lookup denied", inject: func(f *fakeTenantVault) { f.injectFault("/lookup-self", http.StatusForbidden) }, wantErr: "vaultops: look up tenant token", wantRevoke: true},
		{name: "accessor absent", inject: func(f *fakeTenantVault) { f.injectEmptyData("/lookup-self") }, wantErr: "vaultops: accessor missing", wantRevoke: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv, srv := newFakeTenantVault(t, "approle")
			tt.inject(fv)
			admin := newFakeAdminClient(t, srv.URL)

			got, err := OpenTenantSession(context.Background(), admin, TenantSessionRequest{Tenant: "meta-platform"})
			assertSessionFault(t, got, err, tt.wantErr)
			_, revoked := findTenantCall(fv.snapshot(), "/revoke-self")
			if revoked != tt.wantRevoke {
				t.Errorf("revoke-self sent = %v, want %v", revoked, tt.wantRevoke)
			}
		})
	}
}

func assertSessionFault(t *testing.T, got TenantSession, err error, wantErr string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("OpenTenantSession error = %v, want substring %q", err, wantErr)
	}
	if errors.Is(err, ErrWrapConsumed) {
		t.Errorf("OpenTenantSession error = %v, want an error other than ErrWrapConsumed", err)
	}
	if got != (TenantSession{}) {
		t.Errorf("OpenTenantSession session = %+v, want zero session", got)
	}
}

func TestOpenTenantSession_RejectsNilAdmin(t *testing.T) {
	_, err := OpenTenantSession(context.Background(), nil, TenantSessionRequest{Tenant: "meta-platform"})
	if err == nil || err.Error() != "vaultops: nil admin client" {
		t.Errorf("OpenTenantSession(nil admin) error = %v, want vaultops: nil admin client", err)
	}
}

func TestRevokeTenantSession_FailsOnUnusableInput(t *testing.T) {
	fv, srv := newFakeTenantVault(t, "approle")
	fv.injectFault("/revoke-self", http.StatusInternalServerError)
	admin := newFakeAdminClient(t, srv.URL)

	tests := []struct {
		name    string
		session TenantSession
		useNil  bool
		wantErr string
	}{
		{name: "empty token", session: TenantSession{}, wantErr: "vaultops: empty tenant session token"},
		{name: "nil base client", session: TenantSession{Token: fakeTenantToken}, useNil: true, wantErr: "vaultops: nil base client"},
		{name: "revoke rejected", session: TenantSession{Token: fakeTenantToken}, wantErr: "vaultops: revoke tenant session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := admin
			if tt.useNil {
				base = nil
			}
			err := RevokeTenantSession(context.Background(), base, tt.session)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("RevokeTenantSession error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestRevokeTenantSession_RevokesOnlyTheSessionToken(t *testing.T) {
	fv, srv := newFakeTenantVault(t, "approle")
	admin := newFakeAdminClient(t, srv.URL)

	if err := RevokeTenantSession(context.Background(), admin, TenantSession{Token: fakeTenantToken}); err != nil {
		t.Fatalf("RevokeTenantSession: %v", err)
	}
	c, ok := findTenantCall(fv.snapshot(), "/auth/token/revoke-self")
	if !ok {
		t.Fatal("no revoke-self request")
	}
	if c.token != fakeTenantToken {
		t.Errorf("X-Vault-Token on revoke-self = %q, want %q", c.token, fakeTenantToken)
	}
}

func TestBuildTenantSessionEnv(t *testing.T) {
	root := t.TempDir()
	p := NewPaths(root, "", t.TempDir(), "https://172.16.0.1:8200")
	caCert := "VAULT_CACERT=" + filepath.Join(root, "vault", "tls", "ca.pem")
	session := TenantSession{Token: fakeTenantToken}

	tests := []struct {
		name    string
		base    []string
		want    []string
		missing []string
	}{
		{
			name:    "replaces the operator token",
			base:    []string{"HOME=/home/op", "VAULT_TOKEN=" + fakeAdminToken, "PATH=/usr/bin"},
			want:    []string{"HOME=/home/op", "PATH=/usr/bin", "VAULT_TOKEN=" + fakeTenantToken, "VAULT_ADDR=https://172.16.0.1:8200", caCert},
			missing: []string{"VAULT_TOKEN=" + fakeAdminToken},
		},
		{
			name:    "drops duplicate Vault entries",
			base:    []string{"VAULT_ADDR=http://old", "VAULT_ADDR=http://older", "VAULT_CACERT=/old.pem"},
			want:    []string{"VAULT_TOKEN=" + fakeTenantToken, "VAULT_ADDR=https://172.16.0.1:8200", caCert},
			missing: []string{"VAULT_ADDR=http://old", "VAULT_ADDR=http://older", "VAULT_CACERT=/old.pem"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertEnvEntries(t, BuildTenantSessionEnv(tt.base, session, p), tt.want, tt.missing)
		})
	}
}

func assertEnvEntries(t *testing.T, got, want, missing []string) {
	t.Helper()
	for _, entry := range want {
		if !slices.Contains(got, entry) {
			t.Errorf("BuildTenantSessionEnv lacks %q, got %v", entry, got)
		}
	}
	for _, entry := range missing {
		if slices.Contains(got, entry) {
			t.Errorf("BuildTenantSessionEnv kept %q, got %v", entry, got)
		}
	}
	for _, key := range []string{"VAULT_TOKEN=", "VAULT_ADDR=", "VAULT_CACERT="} {
		if n := countEnvPrefix(got, key); n != 1 {
			t.Errorf("BuildTenantSessionEnv holds %d entries with prefix %q, want 1", n, key)
		}
	}
}

func countEnvPrefix(entries []string, prefix string) int {
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e, prefix) {
			n++
		}
	}
	return n
}
