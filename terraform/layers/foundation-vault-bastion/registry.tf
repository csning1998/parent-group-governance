
# The registry publishes the facts which tenants consume, in place of terraform_remote_state on this layer.
# Only this layer writes the mount, hence a tenant cannot widen the facts which bind the tenant.
resource "vault_mount" "registry" {
  provider    = vault.bastion
  path        = "registry"
  type        = "kv"
  options     = { version = "2" }
  description = "Facts which parent-group-governance publishes to tenants. Tenants read, and only parent-group-governance writes."
}

# Each field holds one category in JSON, and a consumer decodes only the consumed field.
resource "vault_kv_secret_v2" "registry_platform_trust" {
  provider = vault.bastion
  mount    = vault_mount.registry.path
  name     = "platform/trust"
  data_json = jsonencode({
    domain_suffix        = local.platform_trust.domain_suffix
    spire_trust_domains  = jsonencode(local.spire_trust_domains)
    network_cidr         = local.platform_trust.network_cidr
    bastion_publish_cidr = local.platform_trust.bastion_publish_cidr
  })
}

resource "vault_kv_secret_v2" "registry_tenant_bastion" {
  for_each = local.tenants

  provider = vault.bastion
  mount    = vault_mount.registry.path
  name     = "${each.key}/bastion"
  data_json = jsonencode({
    vault = jsonencode({
      endpoint             = module.local_credential_contexts.bastion_vault_config.endpoint
      listener_ca_cert_pem = data.local_file.bastion_vault_ca.content
    })
    pki = jsonencode({
      root_cert_pem           = vault_pki_secret_backend_root_cert.root.certificate
      intermediate_cert_pem   = vault_pki_secret_backend_root_sign_intermediate.pki_intermediate_signed.certificate
      intermediate_mount_path = vault_mount.pki_intermediate.path
      constrained_intermediates = {
        for name, mount in vault_mount.pki_constrained : name => {
          mount_path = mount.path
          cert_pem   = vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed[name].certificate
        } if local.constrained_intermediates[name].owner == each.key
      }
    })
    transit_unseal = jsonencode({
      mount_path = vault_mount.transit_unseal.path
      consumers = {
        for name, consumer in local.transit_unseal_consumers : name => {
          key_name    = vault_transit_secret_backend_key.transit_unseal[name].name
          policy_name = vault_policy.transit_unseal[name].name
        } if consumer.owner == each.key
      }
    })
    policy_request = jsonencode({
      mount = local.policy_request_mount
      name  = local.policy_request_names[each.key]
    })
  })
}

# The tenant ACL on sys/policies/acl/<code>-* cannot rewrite the policy, since the policy name lacks the tenant prefix.
resource "vault_policy" "registry_reader" {
  for_each = local.tenants

  provider = vault.bastion
  name     = "registry-reader-${each.key}"
  policy = jsonencode({
    path = {
      "sys/internal/ui/mounts/${vault_mount.registry.path}" = { capabilities = ["read"] }
      "${vault_mount.registry.path}/data/${each.key}/*"     = { capabilities = ["read"] }
      "${vault_mount.registry.path}/data/platform/*"        = { capabilities = ["read"] }
    }
  })
}
