
data "anthropic_organization" "current" {}

ephemeral "vault_kv_secret_v2" "anthropic_console" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/ai-provider-console/anthropic"
}
