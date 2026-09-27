
locals {
  key_vault_name = substr("kv${replace(lower(var.cognitive_account_name), "/[^a-z0-9]/", "")}", 0, 24)

  virtual_network_name         = substr("vnet-${var.cognitive_account_name}", 0, 64)
  private_endpoint_openai_name = substr("pe-${var.cognitive_account_name}", 0, 80)
  private_endpoint_vault_name  = substr("pe-${local.key_vault_name}", 0, 80)

  # The cognitive account ACL drops a /32 prefix because Cognitive Services rejects the prefix.
  cognitive_account_ip_rules = [
    for rule in var.key_vault_ip_rules : replace(rule, "/\\/32$/", "")
  ]

  cognitive_account_fqdns = [
    "${var.cognitive_account_name}.openai.azure.com",
    "${local.key_vault_name}.vault.azure.net",
  ]

  model_deployments = {
    "gpt-5.4-mini" = {
      model = {
        format  = "OpenAI"
        name    = "gpt-5.4-mini"
        version = "2026-03-17"
      }
      sku = {
        name     = "DataZoneStandard"
        capacity = 100
      }
    }
  }
}
