package main

import (
	// "bufio"
	// "bytes"
	// "context"
	// "encoding/json"
	// "encoding/pem"
	"io"
	// "net/http"
	// "net/http/httptest"
	// "os"
	// "path/filepath"
	// "slices"
	// "strings"
	"testing"

	"gitlab.com/csning1998-lab/parent-group-governance/tools/governance/internal/ui"
)

// Deprecated: legacy menu labels retained as comments.
// const (
// 	labelUnseal        = "[Vault] Unseal Bastion Vault"
// 	labelTenantSession = "[Vault] Open Tenant Operator Session"
// )

func TestBuildMenuOptions_EndsWithQuit(t *testing.T) {
	a := &app{out: ui.New(io.Discard, io.Discard)}
	options := a.buildMenuOptions()

	if len(options) == 0 {
		t.Fatal("expected at least one menu option")
	}
	if last := options[len(options)-1]; last.label != "Quit" || last.run != nil {
		t.Errorf("last menu option = %q, want Quit without an action", last.label)
	}
}

// Deprecated: Tenant session tests below are superseded by workstation Vault Proxies.
// func TestRunTenantSessionMenu_StopsWithoutOpeningASession(t *testing.T) {
// 	tests := []struct {
// 		name       string
// 		roles      []string
// 		input      string
// 		wantOutput string
// 	}{
// 		{name: "no tenant role", roles: nil, input: "", wantOutput: "No tenant Terraform operator role exists"},
// 		{name: "invalid selection", roles: []string{"meta-platform-terraform-operator"}, input: "9\n", wantOutput: msgInvalidOption},
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			a, buf := newMenuApp(t, tt.roles, tt.input)
// 			if err := a.runTenantSessionMenu(context.Background()); err != nil {
// 				t.Fatalf("runTenantSessionMenu: %v", err)
// 			}
// 			if !strings.Contains(buf.String(), tt.wantOutput) {
// 				t.Errorf("output = %q, want %q", buf.String(), tt.wantOutput)
// 			}
// 			if strings.Contains(buf.String(), "Tenant session for") {
// 				t.Errorf("output = %q, want no opened session", buf.String())
// 			}
// 		})
// 	}
// }
//
// func TestRunTenantSessionMenu_RequiresTheOperatorToken(t *testing.T) {
// 	a := &app{root: t.TempDir(), home: t.TempDir(), out: ui.New(io.Discard, io.Discard)}
//
// 	err := a.runTenantSessionMenu(context.Background())
// 	if err == nil || !strings.Contains(err.Error(), "root token not found") {
// 		t.Errorf("runTenantSessionMenu error = %v, want the missing root token", err)
// 	}
// }
