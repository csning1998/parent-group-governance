
ephemeral "vault_kv_secret_v2" "state_backend" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/state-backend"
}

module "local_creds" {
  # Resolves relative to the directory containing this file (terraform/layers/<this layer>),
  # two levels up to terraform/, then into modules/local-credential-contexts.
  source = "../../modules/local-credential-contexts"
}

resource "gitlab_group" "this" {
  name             = "Personal Lab"
  path             = "csning1998-lab"
  description      = "A collection of personal projects and experiments."
  visibility_level = "public"
}
