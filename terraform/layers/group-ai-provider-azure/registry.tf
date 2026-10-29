
# Downstream administration layers read the federation identifiers from the registry instead of the state of this layer.
resource "vault_kv_secret_v2" "registry_platform_ai_provider_azure" {
  provider = vault.bastion
  mount    = "registry"
  name     = "platform/ai-provider/azure"
  data_json = jsonencode({
    tenant_id            = data.azuread_client_config.current.tenant_id
    subscription_id      = data.azurerm_client_config.current.subscription_id
    cognitive_account_id = azurerm_cognitive_account.openai.id
    openai_endpoint      = azurerm_cognitive_account.openai.endpoint
  })
}
