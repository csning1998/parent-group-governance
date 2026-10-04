package vaultops

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestListTenantCodes(t *testing.T) {
	tests := []struct {
		name     string
		mountArg string
		servedOn string
		roles    []string
		want     []string
	}{
		{
			name:     "keeps operator roles of valid tenant codes in order",
			servedOn: "approle",
			roles:    []string{"zeta-terraform-operator", "meta-platform-terraform-operator", "spire-upstream-authority", "Bad Code-terraform-operator", "-terraform-operator"},
			want:     []string{"meta-platform", "zeta"},
		},
		{name: "mount without roles", servedOn: "approle", roles: nil, want: []string{}},
		{name: "explicit mount", mountArg: "approle-tenants", servedOn: "approle-tenants", roles: []string{"meta-platform-terraform-operator"}, want: []string{"meta-platform"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fv, srv := newFakeTenantVault(t, tt.servedOn)
			fv.roles = tt.roles
			admin := newFakeAdminClient(t, srv.URL)

			got, err := ListTenantCodes(context.Background(), admin, tt.mountArg)
			if err != nil {
				t.Fatalf("ListTenantCodes: %v", err)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("ListTenantCodes = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestListTenantCodes_FailsWhenTheListIsDenied(t *testing.T) {
	fv, srv := newFakeTenantVault(t, "approle")
	fv.injectFault("/auth/approle/role", http.StatusForbidden)
	admin := newFakeAdminClient(t, srv.URL)

	_, err := ListTenantCodes(context.Background(), admin, "")
	if err == nil || !strings.Contains(err.Error(), "vaultops: list tenant roles") {
		t.Errorf("ListTenantCodes error = %v, want the denied list", err)
	}
}
