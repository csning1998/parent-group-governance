
# Downstream administration layers read the federation identifiers from the registry instead of the state of this layer.
resource "vault_kv_secret_v2" "registry_platform_ai_provider_anthropic" {
  provider = vault.bastion
  mount    = "registry"
  name     = "platform/ai-provider/anthropic"
  data_json = jsonencode({
    issuer_id       = anthropic_federation_issuer.gitlab_saas.id
    organization_id = data.anthropic_organization.current.id
  })
}
