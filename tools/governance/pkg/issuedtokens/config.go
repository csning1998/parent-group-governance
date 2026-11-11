// Package issuedtokens provisions service-issued tokens into Bastion Vault and GitLab without persisting secrets in Terraform state.
package issuedtokens

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// VaultField locates one field of a KV v2 secret.
type VaultField struct {
	Mount string `yaml:"vault_kv_mount"`
	Path  string `yaml:"vault_kv_path"`
	Field string `yaml:"vault_kv_field"`
}

// SonarQubeAnalysisTokenConfig declares configuration for the shared SonarQube analysis token used by group CI pipelines.
type SonarQubeAnalysisTokenConfig struct {
	UserTokensEndpoint     string     `yaml:"user_tokens_endpoint"`      // api/user_tokens web service of the SonarQube instance
	AdminPasswordKey       string     `yaml:"admin_password_key"`        // service_admin_passwords identifier for the token issuing account
	TokenNamePrefix        string     `yaml:"token_name_prefix"`         // name prefix identifying tokens managed by ./governance
	Vault                  VaultField `yaml:"vault"`                     // Bastion Vault secret field storing the token
	GitLabGroupVariableKey string     `yaml:"gitlab_group_variable_key"` // GitLab group CI/CD variable key storing the token
}

// Config is the service_issued_tokens section of workstation-topology.yaml.
type Config struct {
	GitLabAPIURL           string                       `yaml:"gitlab_api_url"`           // GitLab REST API base URL
	GitLabTokenOwnerCode   string                       `yaml:"gitlab_token_owner_code"`  // owner code supplying the state backend token for GitLab variable updates
	GitLabGroupRegistry    VaultField                   `yaml:"gitlab_group_registry"`    // registry field holding the top-level group ID
	SonarQubeAnalysisToken SonarQubeAnalysisTokenConfig `yaml:"sonarqube_analysis_token"` // SonarQube analysis token of the group CI jobs
}

// Load parses the service_issued_tokens section from the topology configuration at path.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("issuedtokens: read %s: %w", path, err)
	}
	var doc struct {
		ServiceIssuedTokens Config `yaml:"service_issued_tokens"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return Config{}, fmt.Errorf("issuedtokens: parse %s: %w", path, err)
	}
	return doc.ServiceIssuedTokens, nil
}
