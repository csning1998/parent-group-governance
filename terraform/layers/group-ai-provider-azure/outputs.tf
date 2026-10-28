
output "tenant" {
  description = "Microsoft Entra ID tenant metadata."
  value = {
    id = data.azuread_client_config.current.tenant_id
  }
}

output "subscription" {
  description = "Azure subscription metadata."
  value = {
    id = data.azurerm_client_config.current.subscription_id
  }
}

output "resource_group" {
  description = "Azure resource group metadata."
  value = {
    name     = azurerm_resource_group.group_federation.name
    location = azurerm_resource_group.group_federation.location
  }
}

output "openai" {
  description = "Azure OpenAI Cognitive Services metadata."
  value = {
    id       = azurerm_cognitive_account.openai.id
    name     = azurerm_cognitive_account.openai.name
    endpoint = azurerm_cognitive_account.openai.endpoint
  }
}

output "deployments" {
  description = "Azure OpenAI model deployments metadata."
  value = {
    for k, v in azurerm_cognitive_deployment.this : k => {
      id   = v.id
      name = v.name
    }
  }
}

output "network" {
  description = "Private endpoint network metadata. Values are null on the free tier."
  value = {
    virtual_network_id  = one(azurerm_virtual_network.group_federation[*].id)
    subnet_id           = one(azurerm_subnet.private_endpoints[*].id)
    private_endpoint_id = one(azurerm_private_endpoint.openai[*].id)
  }
}

output "encryption" {
  description = "Customer managed key metadata for the cognitive account."
  value = {
    key_vault_id = azurerm_key_vault.openai.id
    key_id       = azurerm_key_vault_key.openai.versionless_id
  }
}
