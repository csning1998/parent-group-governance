package vaultops

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// shellProbe records the environment and the Vault request count which the session shell observed.
type shellProbe struct {
	env            []string
	callsDuringRun int
	err            error
	cancel         context.CancelFunc
}

func (s *shellProbe) runner(fv *fakeTenantVault) func(context.Context, []string) error {
	return func(ctx context.Context, env []string) error {
		s.env = env
		s.callsDuringRun = len(fv.snapshot())
		if s.cancel != nil {
			s.cancel()
		}
		return s.err
	}
}

func newTenantRunFixture(t *testing.T) (*fakeTenantVault, Paths, *bytes.Buffer, *ui.Printer) {
	t.Helper()
	fv, srv := newFakeTenantVault(t, "approle")
	p := NewPaths(t.TempDir(), "", t.TempDir(), srv.URL)
	var buf bytes.Buffer
	return fv, p, &buf, ui.New(&buf, &buf)
}

func TestRunTenantSession_RevokesAfterTheShellExits(t *testing.T) {
	fv, p, buf, out := newTenantRunFixture(t)
	admin := newFakeAdminClient(t, p.resolveBastionAddr())
	probe := &shellProbe{}

	shell := TenantShell{Base: []string{"HOME=/home/op", "VAULT_TOKEN=" + fakeAdminToken}, Run: probe.runner(fv)}
	if err := RunTenantSession(context.Background(), p, admin, TenantSessionRequest{Tenant: "meta-platform"}, out, shell); err != nil {
		t.Fatalf("RunTenantSession: %v", err)
	}

	if !slices.Contains(probe.env, "VAULT_TOKEN="+fakeTenantToken) || slices.Contains(probe.env, "VAULT_TOKEN="+fakeAdminToken) {
		t.Errorf("shell env = %v, want the tenant token in place of the operator token", probe.env)
	}
	calls := fv.snapshot()
	if _, revokedEarly := findTenantCall(calls[:probe.callsDuringRun], "/revoke-self"); revokedEarly {
		t.Error("revoke-self was sent before the shell exited")
	}
	assertRevokedWithTenantToken(t, calls)
	if strings.Contains(buf.String(), fakeTenantAccess) || strings.Contains(buf.String(), "accessor") {
		t.Errorf("output = %q, want no token accessor, which the audit devices store only as an HMAC", buf.String())
	}
	if !strings.Contains(buf.String(), "meta-platform") {
		t.Errorf("output = %q, want the tenant name", buf.String())
	}
}

func TestRunTenantSession_RevokesWhenTheShellFailsOrIsCanceled(t *testing.T) {
	shellErr := errors.New("exit status 1")
	tests := []struct {
		name    string
		err     error
		cancel  bool
		wantErr error
	}{
		{name: "shell failure", err: shellErr, wantErr: shellErr},
		{name: "context canceled", err: context.Canceled, cancel: true, wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv, p, _, out := newTenantRunFixture(t)
			admin := newFakeAdminClient(t, p.resolveBastionAddr())
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			probe := &shellProbe{err: tt.err}
			if tt.cancel {
				probe.cancel = cancel
			}

			err := RunTenantSession(ctx, p, admin, TenantSessionRequest{Tenant: "meta-platform"}, out, TenantShell{Run: probe.runner(fv)})
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("RunTenantSession error = %v, want %v", err, tt.wantErr)
			}
			assertRevokedWithTenantToken(t, fv.snapshot())
		})
	}
}

func TestRunTenantSession_SkipsTheShellWhenOpenFails(t *testing.T) {
	fv, p, _, out := newTenantRunFixture(t)
	admin := newFakeAdminClient(t, p.resolveBastionAddr())
	ran := false
	run := func(context.Context, []string) error { ran = true; return nil }

	err := RunTenantSession(context.Background(), p, admin, TenantSessionRequest{Tenant: "Bad Tenant"}, out, TenantShell{Run: run})
	if !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("RunTenantSession error = %v, want ErrInvalidTenant", err)
	}
	if ran {
		t.Error("the shell ran although the session did not open")
	}
	if _, ok := findTenantCall(fv.snapshot(), "/revoke-self"); ok {
		t.Error("revoke-self was sent although the session did not open")
	}
}

func TestRunTenantSession_ReportsARevokeFailure(t *testing.T) {
	fv, p, _, out := newTenantRunFixture(t)
	fv.injectFault("/revoke-self", http.StatusInternalServerError)
	admin := newFakeAdminClient(t, p.resolveBastionAddr())
	probe := &shellProbe{}

	err := RunTenantSession(context.Background(), p, admin, TenantSessionRequest{Tenant: "meta-platform"}, out, TenantShell{Run: probe.runner(fv)})
	if err == nil || !strings.Contains(err.Error(), "vaultops: revoke tenant session") {
		t.Errorf("RunTenantSession error = %v, want the revoke failure", err)
	}
}

func assertRevokedWithTenantToken(t *testing.T, calls []tenantCall) {
	t.Helper()
	c, ok := findTenantCall(calls, "/revoke-self")
	if !ok {
		t.Fatal("no revoke-self request after the shell exited")
	}
	if c.token != fakeTenantToken {
		t.Errorf("X-Vault-Token on revoke-self = %q, want %q", c.token, fakeTenantToken)
	}
}
