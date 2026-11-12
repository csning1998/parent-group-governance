package issuedtokens

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoad asserts the parsing of the service_issued_tokens section and the error for a missing configuration file.
func TestLoad(t *testing.T) {
	t.Run("parses the service_issued_tokens section", testLoadParsesTheSection)
	t.Run("reports a missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "absent.yaml")); err == nil {
			t.Fatal("got no error for a missing file")
		}
	})
}

func testLoadParsesTheSection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workstation-topology.yaml")
	content := `service_issued_tokens:
  gitlab_group_registry:
    vault_kv_mount: "registry"
    vault_kv_path: "platform/gitlab-group/top-level"
    vault_kv_field: "group_id"
  sonarqube_analysis_token:
    user_tokens_endpoint: "http://127.0.0.1:9000/api/user_tokens"
    admin_password_key: "sonarqube-admin-password"
    token_name_prefix: "gitlab-ci-analysis"
    vault:
      vault_kv_mount: "secret"
      vault_kv_path: "example-governance/sonarqube/ci-analysis-bot"
      vault_kv_field: "sonarqube_ci_token"
    gitlab_group_variable_key: "SONAR_TOKEN"
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.GitLabGroupRegistry != (VaultField{Mount: "registry", Path: "platform/gitlab-group/top-level", Field: "group_id"}) {
		t.Fatalf("got %+v", got)
	}
	sonar := got.SonarQubeAnalysisToken
	if sonar.AdminPasswordKey != "sonarqube-admin-password" || sonar.Vault.Field != "sonarqube_ci_token" || sonar.GitLabGroupVariableKey != "SONAR_TOKEN" {
		t.Fatalf("got %+v", sonar)
	}
}
