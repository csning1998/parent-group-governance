
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
resource "vault_kv_secret_v2" "registry_platform_network_allocation" {
  provider = vault.bastion
  mount    = vault_mount.registry.path
  name     = "platform/network/allocation"
  data_json = jsonencode({
    domain_suffix                    = local.network_allocation.domain_suffix
    stage_domains                    = jsonencode(local.stage_domains)
    network_cidr                     = local.network_allocation.network_cidr
    bastion_publish_cidr             = local.network_allocation.bastion_publish_cidr
    host_telemetry_scrape_cidr       = local.host_segment_cidrs.host_telemetry_scrape
    host_telemetry_scrape_address    = local.host_telemetry_scrape_address
    host_log_rendezvous_cidr         = local.host_segment_cidrs.host_log_rendezvous
    host_log_rendezvous_address      = local.host_log_rendezvous_address
    host_log_rendezvous_server_names = jsonencode(local.host_log_rendezvous_server_names)
  })
}

resource "vault_kv_secret_v2" "registry_tenant_bastion" {
  for_each = local.tenants

  provider = vault.bastion
  mount    = vault_mount.registry.path
  name     = "${each.key}/bastion"
  data_json = jsonencode({
    vault = jsonencode({
      endpoint             = local.bastion_vault_endpoint
      listener_ca_cert_pem = data.local_file.bastion_vault_publish_ca.content
      approle_mount_path   = vault_auth_backend.approle.path
    })
    pki = jsonencode({
      trust_anchors = {
        for algo, cert in vault_pki_secret_backend_root_cert.root : algo => cert.certificate
      }
      constrained_intermediates = {
        for name, mount in vault_mount.pki_constrained : name => {
          mount_path = mount.path
          root_ca_id = local.constrained_intermediates[name].root_ca_id
          issuer_certs = {
            for algo_key, _ in local.constrained_intermediate_algorithms : algo_key => vault_pki_secret_backend_root_sign_intermediate.pki_constrained_signed["${name}/${algo_key}"].certificate
          }
          assignable_policy = lookup(local.constrained_assignable_by_mount, name, null)
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
    # Each key names an auth scope: owned for auth/<code>-* mounts, approle and gitlab for the shared mounts.
    assignable_policies = jsonencode(local.tenant_assignable[each.key])
  })
}

# The tenant cannot rewrite the policy, because the tenant ACL does not grant any write on sys/policies/acl.
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
