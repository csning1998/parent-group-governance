
output "organization" {
  description = "Anthropic organization metadata."
  value = {
    id   = data.anthropic_organization.current.id
    name = data.anthropic_organization.current.name
  }
}

output "issuers" {
  description = "Map of Anthropic Workload Identity Federation issuers registered at organization level."
  value = {
    gitlab_saas = {
      id         = anthropic_federation_issuer.gitlab_saas.id
      name       = anthropic_federation_issuer.gitlab_saas.name
      issuer_url = anthropic_federation_issuer.gitlab_saas.issuer_url
    }
  }
}
