
# Each operator identity of workstation-topology.yaml logs in through its Vault Proxy with a client certificate,
# which the local CA of vault/tls signs. A role admits the CN of its own identity alone.
locals {
  operator_proxy = local.workstation.operator_vault_proxy

  operator_credential_distributor_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "credential-distributor"
  }
  operator_tenant_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "tenant"
  }
  operator_administrator_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "administrator"
  }
  operator_credential_rotator_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "credential-rotator"
  }

  # The administrator identity manages every mount, auth method, and audit device which this layer declares.
  foundation_mount_paths = concat(
    [for mount in vault_mount.pki_root : mount.path],
    [vault_mount.transit_unseal.path, vault_mount.registry.path],
    [for mount in vault_mount.pki_constrained : mount.path],
  )
  foundation_auth_paths  = [vault_auth_backend.approle.path, vault_auth_backend.operator_cert.path, vault_jwt_auth_backend.gitlab_saas.path]
  foundation_audit_paths = [vault_audit.file.path, vault_audit.stdout.path]

  operator_policy_names = merge(
    { for name, policy in vault_policy.operator_credential_distributor : name => [policy.name] },
    { for name, policy in vault_policy.operator_administrator : name => [policy.name] },
    { for name, policy in vault_policy.operator_credential_rotator : name => [policy.name] },
    {
      for name in keys(local.operator_tenant_identities) : name => [
        vault_policy.tenant_terraform_operator[trimprefix(name, "tenant-")].name,
        vault_policy.registry_reader[trimprefix(name, "tenant-")].name,
      ]
    },
  )
}

resource "terraform_data" "operator_identities_validation" {
  input = keys(local.operator_proxy.identities)

  lifecycle {
    precondition {
      condition     = alltrue([for identity in values(local.operator_proxy.identities) : contains(["credential-distributor", "tenant", "administrator", "credential-rotator"], identity.access_tier)])
      error_message = "Every identity of workstation-topology.yaml MUST declare access_tier credential-distributor, tenant, administrator, or credential-rotator."
    }
    precondition {
      condition     = length(local.operator_administrator_identities) == 1 && length(local.operator_credential_rotator_identities) == 1
      error_message = "workstation-topology.yaml MUST declare exactly one administrator identity and exactly one credential-rotator identity."
    }
    precondition {
      condition     = length(local.operator_credential_distributor_identities) == 1
      error_message = "workstation-topology.yaml MUST declare exactly one credential-distributor identity, since vault-proxy-env assumes a single credential-distributor Proxy mediates the state-backend token."
    }
    precondition {
      condition     = alltrue([for name in keys(local.operator_tenant_identities) : startswith(name, "tenant-") && contains(keys(local.tenants), trimprefix(name, "tenant-"))])
      error_message = "A tenant identity of workstation-topology.yaml MUST start with tenant- and name a tenant of access-tenant.tf."
    }
  }
}

resource "vault_auth_backend" "operator_cert" {
  provider    = vault.bastion
  type        = "cert"
  path        = local.operator_proxy.cert_auth_mount
  description = "Client certificates of the operator Vault Proxies on the workstation, signed by the local CA."
}

# A credential-distributor identity reads the state backend token and the group keys of workstation-topology.yaml, and writes nothing.
resource "vault_policy" "operator_credential_distributor" {
  for_each = local.operator_credential_distributor_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      { "sys/internal/ui/mounts/${local.operator_proxy.state_backend.vault_kv_mount}/*" = { capabilities = local.acl_capability.read } },
      {
        for p in concat([local.operator_proxy.state_backend.vault_kv_path], each.value.allowed_read_secret_paths) :
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${p}" => { capabilities = local.acl_capability.read }
      },
    )
  })
}

# The administrator identity replaces the root token after the bootstrap. The identity writes policies and auth roles,
# hence the identity equals root in capability, while the token expires, binds the loopback, and names the identity.
resource "vault_policy" "operator_administrator" {
  for_each = local.operator_administrator_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      {
        "sys/mounts"               = { capabilities = local.acl_capability.read }
        "sys/auth"                 = { capabilities = local.acl_capability.read }
        "sys/audit"                = { capabilities = local.acl_capability.list_sudo }
        "sys/policies/acl"         = { capabilities = local.acl_capability.manage }
        "sys/policies/acl/*"       = { capabilities = local.acl_capability.manage }
        "sys/internal/ui/mounts/*" = { capabilities = local.acl_capability.read }

        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${local.governance_owner}/*"     = { capabilities = local.acl_capability.kv_data }
        "${local.operator_proxy.state_backend.vault_kv_mount}/metadata/${local.governance_owner}/*" = { capabilities = local.acl_capability.kv_metadata }
        "${local.operator_proxy.state_backend.vault_kv_mount}/delete/${local.governance_owner}/*"   = { capabilities = local.acl_capability.kv_version }
        "${local.operator_proxy.state_backend.vault_kv_mount}/destroy/${local.governance_owner}/*"  = { capabilities = local.acl_capability.kv_version }
      },
      merge([for mount in local.foundation_mount_paths : {
        "sys/mounts/${mount}"      = { capabilities = local.acl_capability.manage_mount }
        "sys/mounts/${mount}/tune" = { capabilities = local.acl_capability.manage_mount }
        "${mount}/*"               = { capabilities = local.acl_capability.administer }
      }]...),
      # The Vault provider reads and tunes an auth method through sys/mounts/auth/<path>.
      merge([for auth in local.foundation_auth_paths : {
        "sys/auth/${auth}"             = { capabilities = local.acl_capability.manage_mount }
        "sys/auth/${auth}/tune"        = { capabilities = local.acl_capability.manage_mount }
        "sys/mounts/auth/${auth}"      = { capabilities = local.acl_capability.manage_mount }
        "sys/mounts/auth/${auth}/tune" = { capabilities = local.acl_capability.manage_mount }
        "auth/${auth}/*"               = { capabilities = local.acl_capability.administer }
      }]...),
      { for audit in local.foundation_audit_paths : "sys/audit/${audit}" => { capabilities = local.acl_capability.manage_mount } },
    )
  })
}

# The credential-rotator identity reads and writes the Vault document of each service admin password alone.
resource "vault_policy" "operator_credential_rotator" {
  for_each = local.operator_credential_rotator_identities

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
