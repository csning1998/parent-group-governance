
data "vault_kv_secret_v2" "claude_keys" {
  provider = vault.bastion
  mount    = "secret"
  name     = "gitlab-ci-with-code-reviewer/api-key/provider-anthropic"
}
