
# Each operator identity of workstation-topology.yaml logs in through its Vault Proxy with a client certificate,
# which the ML-DSA-87 CA of vault/tls signs. A role admits the CN of its own identity alone.
locals {
  operator_proxy = local.workstation.operator_vault_proxy

  # Derives the access tier and owner code of each proxy identity from its map key per the topology naming contract.
  operator_identity_roles = {
    for name in keys(local.operator_proxy.identities) : name => {
      access_tier = (
        contains(["administrator", "credential-rotator"], name) ? name :
        startswith(name, "credential-distributor-") ? "credential-distributor" :
        startswith(name, "consumer-") ? "consumer" : "tenant"
      )
      owner_code = (
        contains(["administrator", "credential-rotator"], name) ? local.governance_owner :
        startswith(name, "credential-distributor-") ? trimprefix(name, "credential-distributor-") :
        startswith(name, "consumer-") ? trimprefix(name, "consumer-") : name
      )
    }
  }

  operator_credential_distributor_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if local.operator_identity_roles[name].access_tier == "credential-distributor"
  }
  operator_consumer_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if local.operator_identity_roles[name].access_tier == "consumer"
  }
  operator_tenant_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if local.operator_identity_roles[name].access_tier == "tenant"
  }
  operator_administrator_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if local.operator_identity_roles[name].access_tier == "administrator"
  }
  operator_credential_rotator_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if local.operator_identity_roles[name].access_tier == "credential-rotator"
  }

  # Maps every identity executing Terraform to the GitLab state token path of its owner, excluding credential-rotator.
  # The administrator policy writes every path of the map.
  operator_state_backend_paths = {
    for name, role in local.operator_identity_roles : name => "${role.owner_code}/terraform/state-backend" if role.access_tier != "credential-rotator"
  }

  # The administrator identity manages every mount, auth method, and audit device declared by this layer.
  administrator_mount_paths = concat(
    [vault_mount.pki_root.path, vault_mount.transit_unseal.path, vault_mount.registry.path],
    [for mount in vault_mount.pki_constrained : mount.path],
  )
  administrator_auth_paths  = [vault_auth_backend.approle.path, vault_auth_backend.operator_cert.path, vault_jwt_auth_backend.gitlab_saas.path]
  administrator_audit_paths = [vault_audit.file.path, vault_audit.stdout.path]

  operator_policy_names = merge(
    { for name, policy in vault_policy.operator_credential_distributor : name => [policy.name] },
    { for name, policy in vault_policy.operator_consumer : name => [policy.name] },
    { for name, policy in vault_policy.operator_administrator : name => [policy.name] },
    { for name, policy in vault_policy.operator_credential_rotator : name => [policy.name] },
    { for name in keys(local.operator_tenant_identities) : name => [vault_policy.tenant_terraform_operator[name].name, vault_policy.registry_reader[name].name] },
  )
}

# Validates relative Vault KV path segments in operator_identities_validation preconditions.
locals {
  operator_path_pattern = "^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)*$"
}

resource "terraform_data" "operator_identities_validation" {
  input = keys(local.operator_proxy.identities)

  lifecycle {
    precondition {
      condition     = contains(keys(local.operator_proxy.identities), "administrator") && contains(keys(local.operator_proxy.identities), "credential-rotator")
      error_message = "workstation-topology.yaml MUST declare the identities administrator and credential-rotator."
    }
    precondition {
      condition     = alltrue([for role in values(local.operator_identity_roles) : can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", role.owner_code))])
      error_message = "Every identity name of workstation-topology.yaml MUST end in an owner code of lowercase words joined by hyphens."
    }
    precondition {
      condition     = alltrue([for name in keys(local.operator_tenant_identities) : contains(keys(local.tenants), name)])
      error_message = "An identity name without the prefix credential-distributor- or consumer- MUST name a tenant of access-tenant.tf."
    }
    precondition {
      condition = alltrue(flatten([
        for identity in values(local.operator_proxy.identities) : [
          for path in concat(try(identity.allowed_read_secret_paths, []), try(identity.allowed_write_secret_paths, [])) : can(regex(local.operator_path_pattern, path))
        ]
      ]))
      error_message = "Every allowed_read_secret_paths and allowed_write_secret_paths entry MUST be a KV path of whole segments, without + or * wildcards."
    }
    precondition {
      condition = alltrue(flatten([
        for identity in values(local.operator_proxy.identities) : [
          for path in try(identity.allowed_read_registry_paths, []) : can(regex("^platform/[a-z0-9]+(-[a-z0-9]+)*$", path))
        ]
      ]))
      error_message = "Every allowed_read_registry_paths entry MUST name one domain below platform/ of the registry."
    }
    precondition {
      condition = alltrue([
        for identity in values(local.operator_consumer_identities) :
        length(try(identity.allowed_read_secret_paths, [])) == 0 && length(try(identity.allowed_write_secret_paths, [])) == 0
      ])
      error_message = "A consumer identity MUST NOT declare allowed_read_secret_paths or allowed_write_secret_paths because the tier does not read any organization credential."
    }
    precondition {
      condition     = length(distinct([for identity in values(local.operator_proxy.identities) : identity.listen_port])) == length(local.operator_proxy.identities)
      error_message = "Every identity of workstation-topology.yaml MUST declare a distinct listen_port."
    }
  }
}

resource "vault_auth_backend" "operator_cert" {
  provider    = vault.bastion
  type        = "cert"
  path        = local.operator_proxy.cert_auth_mount
  description = "Client certificates of the operator Vault Proxies on the workstation, signed by the local CA."
}

# A credential-distributor identity reads the GitLab token of its owner, the read paths, and the registry domains of
# workstation-topology.yaml, and writes the secrets below its write prefixes alone.
resource "vault_policy" "operator_credential_distributor" {
  for_each = local.operator_credential_distributor_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      { "sys/internal/ui/mounts/${local.operator_proxy.state_backend.vault_kv_mount}/*" = { capabilities = local.acl_capability.read } },
      {
        for p in concat([local.operator_state_backend_paths[each.key]], each.value.allowed_read_secret_paths) :
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${p}" => { capabilities = local.acl_capability.read }
      },
      merge([for p in each.value.allowed_write_secret_paths : {
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${p}/*"     = { capabilities = local.acl_capability.kv_data }
        "${local.operator_proxy.state_backend.vault_kv_mount}/metadata/${p}/*" = { capabilities = local.acl_capability.kv_metadata }
        "${local.operator_proxy.state_backend.vault_kv_mount}/delete/${p}/*"   = { capabilities = local.acl_capability.kv_version }
        "${local.operator_proxy.state_backend.vault_kv_mount}/destroy/${p}/*"  = { capabilities = local.acl_capability.kv_version }
      }]...),
      { for p in try(each.value.allowed_read_registry_paths, []) : "${vault_mount.registry.path}/data/${p}/*" => { capabilities = local.acl_capability.read } },
    )
  })
}

# A consumer identity reads the GitLab token of its owner and the registry domains of workstation-topology.yaml alone.
# The Terraform layers of a repository outside the Bastion tenants thereby read no organization credential.
resource "vault_policy" "operator_consumer" {
  for_each = local.operator_consumer_identities

  provider = vault.bastion
  name     = "operator-${each.key}"
  policy = jsonencode({
    path = merge(
      {
        "sys/internal/ui/mounts/${local.operator_proxy.state_backend.vault_kv_mount}/*"                             = { capabilities = local.acl_capability.read }
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${local.operator_state_backend_paths[each.key]}" = { capabilities = local.acl_capability.read }
      },
      { for p in each.value.allowed_read_registry_paths : "${vault_mount.registry.path}/data/${p}/*" => { capabilities = local.acl_capability.read } },
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
      # The administrator identity writes repository backend tokens and distributor credentials
      # since tenant policies are scoped to the owner code of each tenant alone and the bootstrap root token is revoked.
      merge(
        [
          for p in distinct(concat(
            values(local.operator_state_backend_paths),
            flatten(
              [for identity in local.operator_credential_distributor_identities : identity.allowed_read_secret_paths]
            ),
            )) : {
            "${local.operator_proxy.state_backend.vault_kv_mount}/data/${p}"     = { capabilities = local.acl_capability.kv_data }
            "${local.operator_proxy.state_backend.vault_kv_mount}/metadata/${p}" = { capabilities = local.acl_capability.kv_metadata }
          }
        ]...
      ),
      # Grants administrator read and write access to code reviewer bot tokens, decoupling secret ingestion from distributor identity lifecycles.
      merge(
        [
          for bot in local.workstation.service_issued_tokens.code_reviewer_variables.bot_tokens : {
            "${bot.vault.vault_kv_mount}/data/${bot.vault.vault_kv_path}"     = { capabilities = local.acl_capability.kv_data }
            "${bot.vault.vault_kv_mount}/metadata/${bot.vault.vault_kv_path}" = { capabilities = local.acl_capability.kv_metadata }
          }
        ]...
      ),
      merge(
        [
          for mount in local.administrator_mount_paths : {
            "sys/mounts/${mount}"      = { capabilities = local.acl_capability.manage_mount }
            "sys/mounts/${mount}/tune" = { capabilities = local.acl_capability.manage_mount }
            "${mount}/*"               = { capabilities = local.acl_capability.administer }
          }
        ]...
      ),
      # The Vault provider reads and tunes an auth method through sys/mounts/auth/<path>.
      merge(
        [
          for auth in local.administrator_auth_paths : {
            "sys/auth/${auth}"             = { capabilities = local.acl_capability.manage_mount }
            "sys/auth/${auth}/tune"        = { capabilities = local.acl_capability.manage_mount }
            "sys/mounts/auth/${auth}"      = { capabilities = local.acl_capability.manage_mount }
            "sys/mounts/auth/${auth}/tune" = { capabilities = local.acl_capability.manage_mount }
            "auth/${auth}/*"               = { capabilities = local.acl_capability.administer }
          }
        ]...
      ),
      { for audit in local.administrator_audit_paths : "sys/audit/${audit}" => { capabilities = local.acl_capability.manage_mount } },
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
  certificate          = data.local_file.vault_bastion_operator_ca.content
  allowed_common_names = ["operator-${each.key}"]
  token_policies       = local.operator_policy_names[each.key]
  token_ttl            = 60 * 60
  token_max_ttl        = 60 * 60 * 4
  token_bound_cidrs    = ["${local.workstation.vault_bastion.loopback_address}/32"]
}
