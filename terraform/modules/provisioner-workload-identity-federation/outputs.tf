
output "federation_bindings" {
  description = "Publishes provider workload identity federation bindings and identifiers."
  value = {
    for provider_name, binding in local.bindings : provider_name => binding.document
  }
}

output "anthropic_federation" {
  description = "Publishes Anthropic federation identifiers when enabled."
  value       = try(local.bindings.anthropic.document, null)
}
