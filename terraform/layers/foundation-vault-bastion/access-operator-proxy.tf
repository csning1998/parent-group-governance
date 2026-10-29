
# Each operator identity of workstation-topology.yaml logs in through its Vault Proxy with a client certificate,
# which the ML-DSA-87 CA of vault/tls signs. A role admits the CN of its own identity alone.
locals {
  operator_proxy = local.workstation.operator_vault_proxy

  operator_access_tiers = ["credential-distributor", "consumer", "tenant", "administrator", "credential-rotator"]

  operator_credential_distributor_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "credential-distributor"
  }
  operator_consumer_identities = {
    for name, identity in local.operator_proxy.identities : name => identity if identity.access_tier == "consumer"
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

  # Each identity which runs Terraform reads the GitLab token of its owner, and the administrator writes every token.
  operator_state_backend_paths = {
    for name, identity in local.operator_proxy.identities : name => identity.state_backend_path if can(identity.state_backend_path)
  }
  # A distributor or consumer instance name joins the tier and the owner code. The governance distributor keeps the
  # bare tier name until every downstream repository runs with its own identity.
  operator_owner_scoped_identities = merge(local.operator_credential_distributor_identities, local.operator_consumer_identities)
  operator_path_pattern            = "^[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)*$"

  # The administrator identity manages every mount, auth method, and audit device which this layer declares.
  foundation_mount_paths = concat(
    [vault_mount.pki_root.path, vault_mount.transit_unseal.path, vault_mount.registry.path],
    [for mount in vault_mount.pki_constrained : mount.path],
  )
  foundation_auth_paths  = [vault_auth_backend.approle.path, vault_auth_backend.operator_cert.path, vault_jwt_auth_backend.gitlab_saas.path]
  foundation_audit_paths = [vault_audit.file.path, vault_audit.stdout.path]

  operator_policy_names = merge(
    { for name, policy in vault_policy.operator_credential_distributor : name => [policy.name] },
    { for name, policy in vault_policy.operator_consumer : name => [policy.name] },
    { for name, policy in vault_policy.operator_administrator : name => [policy.name] },
    { for name, policy in vault_policy.operator_credential_rotator : name => [policy.name] },
    { for name in keys(local.operator_tenant_identities) : name => [vault_policy.tenant_terraform_operator[name].name, vault_policy.registry_reader[name].name] },
  )
}

resource "terraform_data" "operator_identities_validation" {
  input = keys(local.operator_proxy.identities)

  lifecycle {
    precondition {
      condition     = alltrue([for identity in values(local.operator_proxy.identities) : contains(local.operator_access_tiers, identity.access_tier)])
      error_message = "Every identity of workstation-topology.yaml MUST declare access_tier credential-distributor, consumer, tenant, administrator, or credential-rotator."
    }
    precondition {
      condition = (
        length(local.operator_administrator_identities) == 1 && contains(keys(local.operator_administrator_identities), "administrator") &&
        length(local.operator_credential_rotator_identities) == 1 && contains(keys(local.operator_credential_rotator_identities), "credential-rotator")
      )
      error_message = "workstation-topology.yaml MUST declare exactly one administrator identity and one credential-rotator identity, each named after its access_tier."
    }
    precondition {
      condition     = alltrue([for identity in values(local.operator_proxy.identities) : can(regex("^[a-z0-9]+(-[a-z0-9]+)*$", identity.owner_code))])
      error_message = "Every identity of workstation-topology.yaml MUST declare owner_code as lowercase words joined by hyphens."
    }
    precondition {
      condition     = alltrue([for name, identity in local.operator_tenant_identities : name == identity.owner_code && contains(keys(local.tenants), name)])
      error_message = "A tenant identity of workstation-topology.yaml MUST be named after its owner_code, which names a tenant of access-tenant.tf."
    }
    precondition {
      condition = alltrue([
        for name, identity in local.operator_owner_scoped_identities :
        name == "${identity.access_tier}-${identity.owner_code}" || (name == identity.access_tier && identity.owner_code == local.governance_owner)
      ])
      error_message = "A credential-distributor or consumer identity MUST be named <access_tier>-<owner_code>, except the governance credential-distributor."
    }
    precondition {
      condition = length(local.operator_owner_scoped_identities) == length(distinct([
        for identity in values(local.operator_owner_scoped_identities) : "${identity.access_tier}/${identity.owner_code}"
      ]))
      error_message = "workstation-topology.yaml MUST declare at most one credential-distributor and one consumer identity per owner_code."
    }
    precondition {
      condition = alltrue([
        for name, identity in local.operator_proxy.identities :
        identity.access_tier == "credential-rotator" || can(identity.state_backend_path)
      ])
      error_message = "Every identity except credential-rotator MUST declare state_backend_path, since vault-proxy-env exports its GitLab token."
    }
    precondition {
      condition = alltrue([
        for name, path in local.operator_state_backend_paths :
        can(regex(local.operator_path_pattern, path)) && startswith(path, "${local.operator_proxy.identities[name].owner_code}/")
      ])
      error_message = "A state_backend_path MUST be a KV path of whole segments below the owner_code of its identity, so an identity reads the GitLab token of its own owner alone."
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
      error_message = "A consumer identity MUST NOT declare allowed_read_secret_paths or allowed_write_secret_paths, since the tier reads no organization credential."
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
        for p in concat([each.value.state_backend_path], each.value.allowed_read_secret_paths) :
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
        "sys/internal/ui/mounts/${local.operator_proxy.state_backend.vault_kv_mount}/*"              = { capabilities = local.acl_capability.read }
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${each.value.state_backend_path}" = { capabilities = local.acl_capability.read }
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
      # The owner writes the GitLab token of each repository, which no tenant ACL or root token covers after revoke-root.
      merge([for p in distinct(values(local.operator_state_backend_paths)) : {
        "${local.operator_proxy.state_backend.vault_kv_mount}/data/${p}"     = { capabilities = local.acl_capability.kv_data }
        "${local.operator_proxy.state_backend.vault_kv_mount}/metadata/${p}" = { capabilities = local.acl_capability.kv_metadata }
      }]...),
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
  certificate          = data.local_file.bastion_vault_operator_ca.content
  allowed_common_names = ["operator-${each.key}"]
  token_policies       = local.operator_policy_names[each.key]
  token_ttl            = 60 * 60
  token_max_ttl        = 60 * 60 * 4
  token_bound_cidrs    = ["${local.workstation.bastion_vault.loopback_address}/32"]
}
