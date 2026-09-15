
data "vault_kv_secret_v2" "claude_keys" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/review-bot-api-keys/claude"
}
