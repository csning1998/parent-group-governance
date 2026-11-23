// Package issuedtokens provisions service issued tokens into Bastion Vault and GitLab without storing secrets in Terraform state.
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
	UserTokensEndpoint     string     `yaml:"user_tokens_endpoint"`
	AdminPasswordKey       string     `yaml:"admin_password_key"`
	TokenNamePrefix        string     `yaml:"token_name_prefix"`
	Vault                  VaultField `yaml:"vault"`
	GitLabGroupVariableKey string     `yaml:"gitlab_group_variable_key"`
}

// GitLabGroupRunnerConfig declares the group runner and the config.toml read by the runner container.
type GitLabGroupRunnerConfig struct {
	Description string   `yaml:"description"`
	TagList     []string `yaml:"tag_list"`
	ConfigPath  string   `yaml:"config_path"` // relative to the project root
}

// ReviewerBotToken maps one bot token in the Bastion Vault to the project variables containing the token.
type ReviewerBotToken struct {
	Vault        VaultField `yaml:"vault"`
	VariableKeys []string   `yaml:"variable_keys"`
}

// CodeReviewerVariablesConfig declares the bot tokens written by ./governance into each listed project.
type CodeReviewerVariablesConfig struct {
	BotTokens []ReviewerBotToken `yaml:"bot_tokens"`
}

// Config is the service_issued_tokens section of workstation-topology.yaml.
type Config struct {
	GitLabGroupRegistry    VaultField                   `yaml:"gitlab_group_registry"`
	SonarQubeAnalysisToken SonarQubeAnalysisTokenConfig `yaml:"sonarqube_analysis_token"`
	GitLabGroupRunner      GitLabGroupRunnerConfig      `yaml:"gitlab_group_runner"`
	CodeReviewerVariables  CodeReviewerVariablesConfig  `yaml:"code_reviewer_variables"`
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
