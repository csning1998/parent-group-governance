
output "anthropic_federation_issuer_id" {
  description = "Anthropic Workload Identity Federation issuer ID managed by this layer."
  value       = anthropic_federation_issuer.gitlab.id
}

output "anthropic_issuer_url" {
  description = "OIDC Issuer URL validated by Anthropic Workload Identity Federation."
  value       = anthropic_federation_issuer.gitlab.issuer_url
}
