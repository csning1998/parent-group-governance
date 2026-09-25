
# The Anthropic provider reads an org:admin OAuth token from ANTHROPIC_AUTH_TOKEN. The token expires within minutes.
resource "anthropic_federation_issuer" "gitlab" {
  name                     = "wif-gitlab-saas-host-admin"
  issuer_url               = "https://gitlab.com"
  check_jti                = true
  max_jwt_lifetime_seconds = 3600
  jwks                     = { type = "discovery" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "vault_kv_secret_v2" "workload_identity_federation" {
  provider = vault.bastion
  mount    = "secret"
  name     = "parent-group-governance/workload-identity-federation/anthropic"
  data_json = jsonencode({
    federation_issuer_id = anthropic_federation_issuer.gitlab.id
    issuer_url           = anthropic_federation_issuer.gitlab.issuer_url
    organization_id      = var.anthropic_organization_id
  })
}

module "local_credential_contexts" {
  source = "../../modules/contexts-local-credential"
}
