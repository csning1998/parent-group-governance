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

// GitLabGroupRunnerConfig declares the group runner and the config.toml which the runner container reads.
type GitLabGroupRunnerConfig struct {
	Description string   `yaml:"description"` // runner description in the group settings and the runner name in config.toml
	TagList     []string `yaml:"tag_list"`    // job tags which the runner accepts
	ConfigPath  string   `yaml:"config_path"` // config.toml path relative to the project root
}

// ReviewerBotToken maps one bot token in the Bastion Vault to the project variables carrying the token.
type ReviewerBotToken struct {
	Vault        VaultField `yaml:"vault"`         // Bastion Vault field holding the bot token
	VariableKeys []string   `yaml:"variable_keys"` // project CI/CD variable keys receiving the bot token
}

// CodeReviewerVariablesConfig declares the bot tokens which ./governance writes into each listed project.
type CodeReviewerVariablesConfig struct {
	BotTokens []ReviewerBotToken `yaml:"bot_tokens"` // bot tokens of the reviewer and the version tag jobs
}

// Config is the service_issued_tokens section of workstation-topology.yaml.
type Config struct {
	GitLabGroupRegistry    VaultField                   `yaml:"gitlab_group_registry"`    // registry field holding the top-level group ID
	SonarQubeAnalysisToken SonarQubeAnalysisTokenConfig `yaml:"sonarqube_analysis_token"` // SonarQube analysis token of the group CI jobs
	GitLabGroupRunner      GitLabGroupRunnerConfig      `yaml:"gitlab_group_runner"`      // group runner of the local Podman executor
	CodeReviewerVariables  CodeReviewerVariablesConfig  `yaml:"code_reviewer_variables"`  // bot tokens of the code reviewer CI components
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
