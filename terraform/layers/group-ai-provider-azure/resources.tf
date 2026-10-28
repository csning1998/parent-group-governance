
resource "azurerm_resource_group" "openai" {
  name     = var.resource_group_name
  location = var.location

  lifecycle {
    prevent_destroy = true
  }
}

resource "azurerm_cognitive_account" "openai" {
  #checkov:skip=CKV_AZURE_134: Standard tier limitation keeps public HTTPS and denies other clients with a network ACL.
  name                = var.cognitive_account_name
  location            = azurerm_resource_group.openai.location
  resource_group_name = azurerm_resource_group.openai.name
  kind                = "OpenAI"
  sku_name            = var.sku_name

  custom_subdomain_name              = var.cognitive_account_name
  public_network_access_enabled      = !var.is_premium_tier
  local_auth_enabled                 = false
  outbound_network_access_restricted = true
  fqdns                              = local.cognitive_account_fqdns

  dynamic "network_acls" {
    for_each = var.is_premium_tier ? [] : [1]

    content {
      default_action = "Deny"
      ip_rules       = local.cognitive_account_ip_rules
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.openai.id]
  }

  # azurerm_cognitive_account_customer_managed_key owns the key, since an account update without this rule removes the key.
  lifecycle {
    prevent_destroy = true
    ignore_changes  = [customer_managed_key]
  }
}

resource "azurerm_cognitive_deployment" "this" {
  for_each = local.model_deployments

  name                 = each.key
  cognitive_account_id = azurerm_cognitive_account.openai.id

  model {
    format  = each.value.model.format
    name    = each.value.model.name
    version = each.value.model.version
  }

  sku {
    name     = each.value.sku.name
    capacity = each.value.sku.capacity
  }
}
