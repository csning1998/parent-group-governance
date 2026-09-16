
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/state-backend"
}

module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}

resource "gitlab_group" "this" {
  name             = "Personal Lab"
  path             = "csning1998-lab"
  description      = "A collection of personal projects and experiments."
  visibility_level = "public"
}
