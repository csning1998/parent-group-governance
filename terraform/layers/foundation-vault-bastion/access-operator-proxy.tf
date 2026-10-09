
# Each operator identity of workstation-topology.yaml logs in through its Vault Proxy with a client certificate,
# which the local CA of vault/tls signs. A role admits the CN of its own identity alone.
locals {
  operator_proxy = local.workstation.operator_proxy

  operator_governance_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access == "governance"
  }
  operator_tenant_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access == "tenant"
  }
  operator_foundation_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access == "foundation"
  }
  operator_rotation_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access == "rotation"
  }

  # Every mount, auth method, and audit device which this layer declares, hence the foundation identity manages them.
  foundation_mount_paths = concat(
    [vault_mount.pki_root.path, vault_mount.pki_intermediate.path, vault_mount.transit_unseal.path, vault_mount.registry.path],
    [for mount in vault_mount.pki_constrained : mount.path],
  )
  foundation_auth_paths  = [vault_auth_backend.approle.path, vault_auth_backend.operator_cert.path, vault_jwt_auth_backend.gitlab_saas.path]
  foundation_audit_paths = [vault_audit.file.path, vault_audit.stdout.path]

  operator_policy_names = merge(
    { for name, policy in vault_policy.operator_governance : name => [policy.name] },
    { for name, policy in vault_policy.operator_foundation : name => [policy.name] },
    { for name, policy in vault_policy.operator_rotation : name => [policy.name] },
    { for name in keys(local.operator_tenant_identities) : name => [vault_policy.tenant_terraform_operator[name].name, vault_policy.registry_reader[name].name] },
  )
}

resource "terraform_data" "operator_identities_validation" {
  input = keys(local.operator_proxy.identities)

  lifecycle {
    precondition {
      condition     = alltrue([for identity in values(local.operator_proxy.identities) : contains(["governance", "tenant", "foundation", "rotation"], identity.access)])
      error_message = "Every identity of workstation-topology.yaml MUST declare access governance, tenant, foundation, or rotation."
    }
    precondition {
      condition     = length(local.operator_foundation_identities) == 1 && length(local.operator_rotation_identities) == 1
      error_message = "workstation-topology.yaml MUST declare exactly one foundation identity and exactly one rotation identity."
    }
    precondition {
      condition     = alltrue([for name in keys(local.operator_tenant_identities) : contains(keys(local.tenants), name)])
      error_message = "A tenant identity of workstation-topology.yaml MUST name a tenant of access-tenant.tf."
    }
  }
}

resource "vault_auth_backend" "operator_cert" {
  provider    = vault.bastion
  type        = "cert"
  path        = local.operator_proxy.cert_auth_mount
  description = "Client certificates of the operator Vault Proxies on the workstation, signed by the local CA."
}

# A governance identity reads the state backend token and the group keys of workstation-topology.yaml, and writes nothing.
resource "vault_policy" "operator_governance" {
  for_each = local.operator_governance_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      { "sys/internal/ui/mounts/${local.operator_proxy.state_backend.mount}/*" = { capabilities = local.acl_capability.read } },
      {
        for p in concat([local.operator_proxy.state_backend.path], each.value.reads) :
        "${local.operator_proxy.state_backend.mount}/data/${p}" => { capabilities = local.acl_capability.read }
      },
    )
  })
}

# The foundation identity replaces the root token after the bootstrap. The identity writes policies and auth roles,
# hence the identity equals root in capability, while the token expires, binds the loopback, and names the identity.
resource "vault_policy" "operator_foundation" {
  for_each = local.operator_foundation_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      {
        "sys/mounts"                                                         = { capabilities = local.acl_capability.read }
        "sys/auth"                                                           = { capabilities = local.acl_capability.read }
        "sys/audit"                                                          = { capabilities = local.acl_capability.list_sudo }
        "sys/policies/acl"                                                   = { capabilities = local.acl_capability.manage }
        "sys/policies/acl/*"                                                 = { capabilities = local.acl_capability.manage }
        "sys/internal/ui/mounts/*"                                           = { capabilities = local.acl_capability.read }
        "${local.operator_proxy.state_backend.mount}/data/${each.key}/*"     = { capabilities = local.acl_capability.kv_data }
        "${local.operator_proxy.state_backend.mount}/metadata/${each.key}/*" = { capabilities = local.acl_capability.kv_metadata }
        "${local.operator_proxy.state_backend.mount}/delete/${each.key}/*"   = { capabilities = local.acl_capability.kv_version }
        "${local.operator_proxy.state_backend.mount}/destroy/${each.key}/*"  = { capabilities = local.acl_capability.kv_version }
      },
      merge([for mount in local.foundation_mount_paths : {
        "sys/mounts/${mount}"      = { capabilities = local.acl_capability.manage_mount }
        "sys/mounts/${mount}/tune" = { capabilities = local.acl_capability.manage_mount }
        "${mount}/*"               = { capabilities = local.acl_capability.administer }
      }]...),
      merge([for auth in local.foundation_auth_paths : {
        "sys/auth/${auth}"      = { capabilities = local.acl_capability.manage_mount }
        "sys/auth/${auth}/tune" = { capabilities = local.acl_capability.manage_mount }
        "auth/${auth}/*"        = { capabilities = local.acl_capability.administer }
      }]...),
      { for audit in local.foundation_audit_paths : "sys/audit/${audit}" => { capabilities = local.acl_capability.manage_mount } },
    )
  })
}

# The rotation identity reads and writes the Vault document of each service admin password alone.
resource "vault_policy" "operator_rotation" {
  for_each = local.operator_rotation_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge([for password in local.workstation.service_admin_passwords : {
      "${password.vault_kv_mount}/data/${password.vault_kv_path}"     = { capabilities = local.acl_capability.kv_rotate }
      "${password.vault_kv_mount}/metadata/${password.vault_kv_path}" = { capabilities = local.acl_capability.read }
    }]...)
  })
}

resource "vault_cert_auth_backend_role" "operator" {
  for_each   = local.operator_proxy.identities
  depends_on = [terraform_data.operator_identities_validation]

  provider             = vault.bastion
  backend              = vault_auth_backend.operator_cert.path
  name                 = "operator-${each.key}"
  certificate          = data.local_file.bastion_vault_ca.content
  allowed_common_names = ["operator-${each.key}"]
  token_policies       = local.operator_policy_names[each.key]
  token_ttl            = 60 * 60
  token_max_ttl        = 60 * 60 * 4
  token_bound_cidrs    = ["${local.workstation.bastion_vault.loopback_address}/32"]
}
