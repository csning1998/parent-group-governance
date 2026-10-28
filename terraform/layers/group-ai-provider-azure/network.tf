resource "azurerm_virtual_network" "group_federation" {
  count = var.is_premium_tier ? 1 : 0

  name                = local.virtual_network_name
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name
  address_space       = var.virtual_network_address_space
}

resource "azurerm_network_security_group" "private_endpoints" {
  count = var.is_premium_tier ? 1 : 0

  name                = "nsg-private-endpoints"
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name

  security_rule {
    name                       = "DenyInternetRdp"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "DenyInternetSsh"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet" "private_endpoints" {
  count = var.is_premium_tier ? 1 : 0

  name                 = "snet-private-endpoints"
  resource_group_name  = azurerm_resource_group.group_federation.name
  virtual_network_name = azurerm_virtual_network.group_federation[count.index].name
  address_prefixes     = [var.private_endpoint_subnet_prefix]

  private_endpoint_network_policies = "Disabled"

  service_endpoint {
    service = "Microsoft.KeyVault"
  }
}

resource "azurerm_subnet_network_security_group_association" "private_endpoints" {
  count = var.is_premium_tier ? 1 : 0

  subnet_id                 = azurerm_subnet.private_endpoints[count.index].id
  network_security_group_id = azurerm_network_security_group.private_endpoints[count.index].id
}

resource "azurerm_private_dns_zone" "openai" {
  count = var.is_premium_tier ? 1 : 0

  name                = "privatelink.openai.azure.com"
  resource_group_name = azurerm_resource_group.group_federation.name
}

resource "azurerm_private_dns_zone" "vault" {
  count = var.is_premium_tier ? 1 : 0

  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = azurerm_resource_group.group_federation.name
}

resource "azurerm_private_dns_zone_virtual_network_link" "openai" {
  count = var.is_premium_tier ? 1 : 0

  name                 = "link-openai"
  private_dns_zone_id  = azurerm_private_dns_zone.openai[count.index].id
  virtual_network_id   = azurerm_virtual_network.group_federation[count.index].id
  registration_enabled = false
}

resource "azurerm_private_dns_zone_virtual_network_link" "vault" {
  count = var.is_premium_tier ? 1 : 0

  name                 = "link-vault"
  private_dns_zone_id  = azurerm_private_dns_zone.vault[count.index].id
  virtual_network_id   = azurerm_virtual_network.group_federation[count.index].id
  registration_enabled = false
}

resource "azurerm_private_endpoint" "openai" {
  count = var.is_premium_tier ? 1 : 0

  name                = local.private_endpoint_openai_name
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name
  subnet_id           = azurerm_subnet.private_endpoints[count.index].id

  private_service_connection {
    name                           = local.private_endpoint_openai_name
    private_connection_resource_id = azurerm_cognitive_account.openai.id
    subresource_names              = ["account"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "openai"
    private_dns_zone_ids = [azurerm_private_dns_zone.openai[count.index].id]
  }
}

resource "azurerm_private_endpoint" "vault" {
  count = var.is_premium_tier ? 1 : 0

  name                = local.private_endpoint_vault_name
  location            = azurerm_resource_group.group_federation.location
  resource_group_name = azurerm_resource_group.group_federation.name
  subnet_id           = azurerm_subnet.private_endpoints[count.index].id

  private_service_connection {
    name                           = local.private_endpoint_vault_name
    private_connection_resource_id = azurerm_key_vault.openai.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "vault"
    private_dns_zone_ids = [azurerm_private_dns_zone.vault[count.index].id]
  }
}
