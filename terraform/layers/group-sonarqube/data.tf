
ephemeral "vault_kv_secret_v2" "sonarqube_admin" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/sonarqube/admin-account"
}
