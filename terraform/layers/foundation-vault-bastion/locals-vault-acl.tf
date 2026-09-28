# The tenant ACL is assembled from named capability sets and rule categories, then rendered once in tenant_acl_policy.
locals {
  acl_capability = {
    read         = ["read"]
    issue        = ["create", "update"]
    configure    = ["create", "read", "update"]
    manage       = ["create", "read", "update", "delete", "list"]
    manage_mount = ["create", "read", "update", "delete", "sudo"]
    kv_data      = ["create", "read", "update", "delete"]
    kv_metadata  = ["read", "list", "delete"]
    kv_version   = ["update"]
  }

  acl_category_order = ["kv", "auth_mount", "auth_role", "policy", "pki", "cross_tenant"]

  acl_category_title = {
    kv           = "KV v2 access inside the tenant namespace."
    auth_mount   = "Auth mounts prefixed by the tenant owner code."
    auth_role    = "AppRole and JWT roles prefixed by the tenant owner code."
    policy       = "ACL policies prefixed by the tenant owner code."
    pki          = "Leaf certificate roles and issuance under the Bootstrap Issuing Intermediate."
    cross_tenant = "Granted outside the tenant namespace by an explicit owner decision."
  }

  # Every grant names its path and its reason.
  acl_cross_tenant_grants = {
    "meta-platform" = [
      {
        path       = "secret/data/parent-group-governance/terraform/state-backend"
        capability = "read"
        reason     = "governance-gitlab-project reads the token which authenticates against the upstream Terraform state."
      },
      {
        path       = "secret/data/parent-group-governance/github/publication"
        capability = "read"
        reason     = "governance-gitlab-project reads the GitHub credential which publishes the project mirror."
      },
      {
        path       = "${local.bastion_pki_intermediate_mount_path}/root/sign-intermediate"
        capability = "issue"
        reason     = "security-vault-downstream-pki signs the Downstream Issuing Intermediate CSR at the Bootstrap Issuing Intermediate."
      },
    ]
  }

  acl_rules = {
    for code in keys(local.tenants) : code => {
      kv = [
        { path = "sys/internal/ui/mounts/secret/*", capability = "read" },
        { path = "secret/data/${code}/*", capability = "kv_data" },
        { path = "secret/metadata/${code}/*", capability = "kv_metadata" },
        { path = "secret/delete/${code}/*", capability = "kv_version" },
        { path = "secret/destroy/${code}/*", capability = "kv_version" },
      ]
      auth_mount = [
        { path = "sys/auth", capability = "read" },
        { path = "sys/auth/${code}-*", capability = "manage_mount" },
        { path = "sys/mounts/auth/${code}-*", capability = "configure" },
        { path = "auth/${code}-*", capability = "manage" },
      ]
      auth_role = [
        { path = "auth/${vault_auth_backend.approle.path}/role/${code}-*", capability = "manage" },
        { path = "auth/${vault_jwt_auth_backend.gitlab_saas.path}/role/${code}-*", capability = "manage" },
      ]
      policy = [
        { path = "sys/policies/acl/${code}-*", capability = "manage" },
      ]
      pki = [
        { path = "sys/mounts/${local.bastion_pki_intermediate_mount_path}", capability = "read" },
        { path = "${local.bastion_pki_intermediate_mount_path}/roles/${code}-*", capability = "manage" },
        { path = "${local.bastion_pki_intermediate_mount_path}/issue/${code}-*", capability = "issue" },
      ]
      cross_tenant = [
        for grant in lookup(local.acl_cross_tenant_grants, code, []) : { path = grant.path, capability = grant.capability }
      ]
    }
  }

  tenant_acl_policy = {
    for code, categories in local.acl_rules : code => join("\n\n", [
      for category in local.acl_category_order : format(
        "# %s\n%s",
        local.acl_category_title[category],
        join("\n", [
          for rule in categories[category] : format(
            "path %s {\n  capabilities = %s\n}",
            jsonencode(rule.path),
            jsonencode(local.acl_capability[rule.capability]),
          )
        ]),
      ) if length(categories[category]) > 0
    ])
  }
}
