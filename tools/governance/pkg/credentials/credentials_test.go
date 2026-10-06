package credentials

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fixturePath = "testdata/fixture.yaml"

func TestLoadMissingFileReturnsZeroConfigNoError(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Credentials) != 0 {
		t.Errorf("len(cfg.Credentials) = %d, want 0", len(cfg.Credentials))
	}
}

func TestLoadParsesVaultOverrideAndCredentials(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Vault.Address != "https://vault.example.internal:8200" {
		t.Errorf("Vault.Address = %q, want the fixture override", cfg.Vault.Address)
	}
	if len(cfg.Credentials) != 1 || cfg.Credentials[0].Key != "sonarqube-password" {
		t.Fatalf("Credentials = %+v, want one entry keyed sonarqube-password", cfg.Credentials)
	}
}

func TestConfigRegistryDerivesVaultFieldFromKey(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("len(creds) = %d, want 1", len(creds))
	}
	cred := creds[0]
	if cred.Key != "sonarqube-password" {
		t.Errorf("Key = %q, want sonarqube-password", cred.Key)
	}
	if cred.Spec.Mount != "secret" || cred.Spec.Path != "parent-group-governance/infrastructure" {
		t.Errorf("Vault location = %s/%s, unexpected", cred.Spec.Mount, cred.Spec.Path)
	}
	if cred.Spec.Field != "sonarqube_password" {
		t.Errorf("Spec.Field = %q, want the snake_case form of Key %q (no separate declaration, Vault field names are always snake_case)", cred.Spec.Field, cred.Key)
	}
}

func TestConfigRegistryAlwaysUsesFullComplexityClasses(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	cred := creds[0]
	if cred.Spec.Length != 24 {
		t.Errorf("Spec.Length = %d, want 24", cred.Spec.Length)
	}
	if len(cred.Spec.Classes) != 4 {
		t.Errorf("len(Spec.Classes) = %d, want 4 (upper, lower, digit, special always required, not configurable)", len(cred.Spec.Classes))
	}
}

func TestConfigRegistryDerivesDefaultPreviousFromFactoryDefaultPassword(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if creds[0].Spec.FactoryDefaultPassword != "admin" {
		t.Errorf("Spec.FactoryDefaultPassword = %q, want %q", creds[0].Spec.FactoryDefaultPassword, "admin")
	}
}

func TestConfigRegistryBuildsApplyFromHTTPFormMechanism(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if creds[0].Spec.Deploy == nil {
		t.Error("Spec.Deploy is nil, want a function built from the http_form mechanism")
	}
}

func TestConfigRegistryBuildsVerifyFromHTTPFormMechanism(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if creds[0].Spec.Verify == nil {
		t.Error("Spec.Verify is nil, want a function built from verify_endpoint")
	}
}

// TestConfigRegistryRejectsHTTPFormWithoutVerifyEndpoint covers a declaration which leaves the
// live credential unobservable. The registry MUST reject the declaration by name.
func TestConfigRegistryRejectsHTTPFormWithoutVerifyEndpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	unverifiable := `
credentials:
  - key: unverifiable
    vault_kv_mount: secret
    vault_kv_path: x
    length: 16
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1:9000/api/users/change_password
      login: admin
`
	if err := os.WriteFile(path, []byte(unverifiable), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildCredentials(); err == nil {
		t.Fatal("Registry: want an error for http_form without verify_endpoint, got nil")
	}
}

func TestConfigRegistryUnknownMechanismErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	bad := `
credentials:
  - key: bad
    vault_kv_mount: secret
    vault_kv_path: x
    length: 16
    service:
      mechanism: does_not_exist
`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, err := cfg.BuildCredentials(); err == nil {
		t.Fatal("Registry: want error for an unknown mechanism, got nil")
	}
}

// TestConfigRegistryRejectsFieldCollisionAcrossDifferentKeys covers two differently-spelled keys
// (dash vs underscore) that normalize to the same Vault field at the same Vault path. Registry
// MUST reject the collision by name instead of letting one silently overwrite the other value.
func TestConfigRegistryRejectsFieldCollisionAcrossDifferentKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	collision := `
credentials:
  - key: sonar-qube-password
    vault_kv_mount: secret
    vault_kv_path: app/infra
    length: 16
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1/a
      verify_endpoint: http://127.0.0.1/a/validate
      login: admin
  - key: sonar_qube_password
    vault_kv_mount: secret
    vault_kv_path: app/infra
    length: 16
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1/b
      verify_endpoint: http://127.0.0.1/b/validate
      login: admin
`
	if err := os.WriteFile(path, []byte(collision), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	_, err = cfg.BuildCredentials()
	if err == nil {
		t.Fatal("Registry: want error for two keys colliding on the same Vault field, got nil")
	}
	if !strings.Contains(err.Error(), "sonar-qube-password") || !strings.Contains(err.Error(), "sonar_qube_password") {
		t.Errorf("error = %q, want it to name both colliding keys", err.Error())
	}
}

func TestLookupFindsAndMissesByKey(t *testing.T) {
	cfg, err := Load(fixturePath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if _, ok := Lookup(creds, "sonarqube-password"); !ok {
		t.Error("Lookup(sonarqube-password) = not found, want found")
	}
	if _, ok := Lookup(creds, "does-not-exist"); ok {
		t.Error("Lookup(does-not-exist) = found, want not found")
	}
}

// TestLoadRejectsTypeConfusionInLengthField covers a crafted YAML document supplying a string
// where the schema declares an int. Load MUST fail rather than silently coerce or zero the field.
func TestLoadRejectsTypeConfusionInLengthField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	bad := `
credentials:
  - key: bad
    vault_kv_mount: secret
    vault_kv_path: x
    length: "not-a-number"
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1/x
      login: admin
`
	if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load: want error for a non-numeric length field, got nil")
	}
}

// TestLoadBoundsAliasExpansionCost covers a crafted YAML document chaining self-referencing aliases
// to force exponential expansion at parse time. Load MUST return within a short bound
// instead of hanging or exhausting memory.
func TestLoadBoundsAliasExpansionCost(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("a0: &a0 [\"x\"]\n")
	for i := 1; i <= 12; i++ {
		fmt.Fprintf(&doc, "a%d: &a%d [*a%d, *a%d]\n", i, i, i-1, i-1)
	}
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte(doc.String()), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	done := make(chan struct{})
	go func() {
		_, _ = Load(path)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Load did not return within 3s against a crafted alias-expansion document")
	}
}

// TestConfigRegistryDuplicateKeysLookupReturnsFirst covers two credentials declaring the same key.
// Registry MUST NOT silently drop either entry, and Lookup MUST resolve to the first-declared one deterministically.
func TestConfigRegistryDuplicateKeysLookupReturnsFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	dup := `
credentials:
  - key: dup
    vault_kv_mount: secret
    vault_kv_path: a
    length: 16
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1/a
      verify_endpoint: http://127.0.0.1/a/validate
      login: admin
  - key: dup
    vault_kv_mount: secret
    vault_kv_path: b
    length: 16
    service:
      mechanism: http_form
      endpoint: http://127.0.0.1/b
      verify_endpoint: http://127.0.0.1/b/validate
      login: admin
`
	if err := os.WriteFile(path, []byte(dup), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	creds, err := cfg.BuildCredentials()
	if err != nil {
		t.Fatalf("Registry: %v", err)
	}
	if len(creds) != 2 {
		t.Fatalf("len(creds) = %d, want 2, Registry does not deduplicate", len(creds))
	}
	got, ok := Lookup(creds, "dup")
	if !ok || got.Spec.Path != "a" {
		t.Errorf("Lookup(dup) = %+v, ok=%v, want the first-declared entry with path a", got, ok)
	}
}
