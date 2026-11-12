
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/terraform/state-backend"
}


resource "gitlab_group" "this" {
  name             = "Personal Lab"
  path             = var.gitlab_top_level_group_path
  description      = "A collection of personal projects and experiments."
  visibility_level = "public"
}
