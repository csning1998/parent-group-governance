
resource "azurerm_key_vault" "openai" {
  name                = local.key_vault_name
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = var.is_premium_tier ? "premium" : "standard"

  rbac_authorization_enabled = true
  purge_protection_enabled   = true
  soft_delete_retention_days = 90

  public_network_access_enabled = !var.is_premium_tier

  network_acls {
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = var.key_vault_ip_rules
    virtual_network_subnet_ids = azurerm_subnet.private_endpoints[*].id
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = length(local.key_vault_name) >= 3 && length(local.key_vault_name) <= 24
      error_message = "The derived Key Vault name must contain 3 to 24 alphanumeric characters."
    }
  }
}

resource "azurerm_user_assigned_identity" "openai" {
  name                = substr("id-${var.cognitive_account_name}", 0, 128)
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_role_assignment" "current_key_vault_admin" {
  scope                = azurerm_key_vault.openai.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = data.azurerm_client_config.current.object_id
}

resource "azurerm_role_assignment" "cognitive_encryption" {
  scope                            = azurerm_key_vault.openai.id
  role_definition_name             = "Key Vault Crypto Service Encryption User"
  principal_id                     = azurerm_user_assigned_identity.openai.principal_id
  skip_service_principal_aad_check = true
}

resource "azurerm_key_vault_key" "openai" {
  #checkov:skip=CKV_AZURE_112: Free tier limitation uses software RSA because an HSM key requires the premium SKU.
  name         = "cognitive-account"
  key_vault_id = azurerm_key_vault.openai.id
  key_type     = var.is_premium_tier ? "RSA-HSM" : "RSA"
  key_size     = 2048
  key_opts     = ["unwrapKey", "wrapKey"]

  expiration_date = var.cmk_expiration_date

  depends_on = [azurerm_role_assignment.current_key_vault_admin]
}

resource "azurerm_cognitive_account_customer_managed_key" "openai" {
  cognitive_account_id = azurerm_cognitive_account.openai.id
  key_vault_key_id     = azurerm_key_vault_key.openai.id
  identity_client_id   = azurerm_user_assigned_identity.openai.client_id

  depends_on = [azurerm_role_assignment.cognitive_encryption]

  lifecycle {
    prevent_destroy = true
  }
}
