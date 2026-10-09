
# Each key names a Vault cluster which auto-unseals against the Bastion Vault, and owner names its tenant.
# The tenant cannot rewrite the policy, because the tenant ACL does not grant any write on sys/policies/acl.
locals {
  transit_unseal_consumers = {
    "${local.platform_tenant}-vault-downstream" = { owner = local.platform_tenant }
  }
}

resource "vault_mount" "transit_unseal" {
  provider    = vault.bastion
  path        = "transit-unseal"
  type        = "transit"
  description = "Transit keys with which downstream Vault clusters auto-unseal. The mount stays apart from the PKI mounts."
}

# The key never leaves the Bastion Vault. exportable and allow_plaintext_backup cannot return to false once set.
resource "vault_transit_secret_backend_key" "transit_unseal" {
  for_each = local.transit_unseal_consumers

  provider               = vault.bastion
  backend                = vault_mount.transit_unseal.path
  name                   = each.key
  type                   = "aes256-gcm96"
  exportable             = false
  allow_plaintext_backup = false
  deletion_allowed       = false
}

# The seal renews its token through renew-self alone, and the token lacks the default policy and with it revoke-self.
resource "vault_policy" "transit_unseal" {
  for_each = local.transit_unseal_consumers

  provider = vault.bastion
  name     = "transit-unseal-${each.key}"
  policy = jsonencode({
    path = {
      "${vault_mount.transit_unseal.path}/encrypt/${vault_transit_secret_backend_key.transit_unseal[each.key].name}" = { capabilities = ["update"] }
      "${vault_mount.transit_unseal.path}/decrypt/${vault_transit_secret_backend_key.transit_unseal[each.key].name}" = { capabilities = ["update"] }
      "auth/token/renew-self"                                                                                        = { capabilities = ["update"] }
    }
  })
}
