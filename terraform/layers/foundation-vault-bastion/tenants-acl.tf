
# A tenant writes no policy, since Vault OSS bounds neither the content of a policy nor the policies of an auth role.
locals {
  acl_capability = {
    read         = ["read"]
    issue        = ["create", "update"]
    configure    = ["create", "read", "update"]
    manage       = ["create", "read", "update", "delete", "list"]
    manage_mount = ["create", "read", "update", "delete", "sudo"]
    kv_data      = ["create", "read", "update", "delete"]
    kv_metadata  = ["create", "read", "update", "list", "delete"]
    kv_version   = ["update"]
  }

  # Every grant outside the tenant prefix names its path and its reason.
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
        path       = "${vault_mount.pki_constrained["pki-downstream"].path}/root/sign-intermediate"
        capability = "issue"
        reason     = "security-vault-downstream-pki signs the Downstream Vault intermediate CA inside a tenant session."
      },
    ]
  }

  # A tenant manages leaf roles only on a constrained leaf mount of the tenant, which cannot issue a Bastion name.
  tenant_leaf_mounts = {
    for code in keys(local.tenants) : code => [
      for mount, spec in local.constrained_intermediates : vault_mount.pki_constrained[mount].path
      if spec.owner == code && spec.max_path_length == 0
    ]
  }

  # A rule with an assign scope writes auth roles, and the policy parameters of the rule stay within the scope ceiling.
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
        { path = "auth/${code}-*", capability = "manage", assign_scope = "owned" },
      ]
      auth_role = [
        { path = "auth/${vault_auth_backend.approle.path}/role/${code}-*", capability = "manage", assign_scope = "approle" },
        { path = "auth/${local.gitlab_saas_jwt_mount_path}/role/${code}-*", capability = "manage", assign_scope = "gitlab" },
      ]
      pki = flatten([
        for mount in local.tenant_leaf_mounts[code] : [
          { path = "sys/mounts/${mount}", capability = "read" },
          { path = "${mount}/roles/${code}-*", capability = "manage" },
          { path = "${mount}/issue/${code}-*", capability = "issue" },
        ]
      ])
      cross_tenant = [
        for grant in lookup(local.acl_cross_tenant_grants, code, []) : { path = grant.path, capability = grant.capability }
      ]
    }
  }

  # Exact names only, since a glob such as <code>-* admits the comma separated string "<code>-a,other".
  # Each auth scope admits only the assignable policies which name the scope, and transit unseal stays on owned mounts.
  tenant_assignable = {
    for code in keys(local.tenants) : code => {
      for scope in ["owned", "approle", "gitlab"] : scope => concat(
        ["default", vault_policy.registry_reader[code].name],
        sort([
          for name, policy in local.constrained_assignable : vault_policy.pki_constrained_assignable[name].name
          if policy.owner == code && contains(policy.scopes, scope)
        ]),
        scope != "owned" ? [] : sort([
          for name, consumer in local.transit_unseal_consumers : vault_policy.transit_unseal[name].name if consumer.owner == code
        ]),
      )
    }
  }

  # A path declared twice fails the plan with a duplicate object key, instead of a silent override.
  acl_entries = {
    for code, categories in local.acl_rules : code => {
      for rule in flatten(values(categories)) : rule.path => rule
    }
  }

  acl_assign_parameters = {
    for code, entries in local.acl_entries : code => {
      for path, rule in entries : path => {
        "token_policies" = local.tenant_assignable[code][rule.assign_scope]
        "policies"       = local.tenant_assignable[code][rule.assign_scope]
        "*"              = []
      } if lookup(rule, "assign_scope", null) != null
    }
  }

  # The inner filter yields zero or one entry, since a conditional cannot unify objects of different attributes.
  tenant_acl_document = {
    for code, entries in local.acl_entries : code => {
      path = {
        for path, rule in entries : path => merge(
          { capabilities = local.acl_capability[rule.capability] },
          { for scoped_path, parameters in local.acl_assign_parameters[code] : "allowed_parameters" => parameters if scoped_path == path },
        )
      }
    }
  }
}
