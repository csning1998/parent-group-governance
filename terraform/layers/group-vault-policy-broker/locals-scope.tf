
# A tenant writes no policy. A tenant which writes both a policy and an auth role mints a token of any policy, since
# Vault OSS bounds neither the content of a policy nor the policies of an auth role. The broker writes every policy
# of a tenant after the checks below, and every auth role write of a tenant names only the exact policies listed here.
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
    renew        = ["update"]
  }

  # Every grant names its path and its reason.
  acl_cross_tenant_grants = {
    "meta-platform" = [
      {
        path       = "secret/data/parent-group-governance/terraform/state-backend"
        capability = "read"
        reason     = "governance-gitlab-project and the Terraform operators read the token which authenticates against the upstream Terraform state."
      },
      {
        path       = "secret/data/parent-group-governance/github/publication"
        capability = "read"
        reason     = "governance-gitlab-project reads the GitHub credential which publishes the project mirror."
      },
      {
        path       = "${local.pki_mount}/root/sign-intermediate"
        capability = "issue"
        reason     = "security-vault-downstream-pki and the SPIRE Parent upstream authority sign their intermediate CA at the Bootstrap Issuing Intermediate."
      },
    ]
  }

  # The tenant ACL. A rule with restrict_policies writes auth roles, and its policy parameters stay within the ceiling.
  acl_category_order = ["kv", "auth_mount", "auth_role", "pki", "cross_tenant"]

  acl_rules = {
    for code in local.owner_codes : code => {
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
        { path = "auth/${code}-*", capability = "manage", restrict_policies = true },
      ]
      auth_role = [
        { path = "auth/${local.approle_mount}/role/${code}-*", capability = "manage", restrict_policies = true },
        { path = "auth/${local.gitlab_mount}/role/${code}-*", capability = "manage", restrict_policies = true },
      ]
      pki = [
        { path = "sys/mounts/${local.pki_mount}", capability = "read" },
        { path = "${local.pki_mount}/roles/${code}-*", capability = "manage" },
        { path = "${local.pki_mount}/issue/${code}-*", capability = "issue" },
      ]
      cross_tenant = [
        for grant in lookup(local.acl_cross_tenant_grants, code, []) : { path = grant.path, capability = grant.capability }
      ]
    }
  }

  # The scope of a requested policy. exact matches the path, and prefix matches every path which begins with the value.
  # The capabilities of a requested rule MUST stay within the capabilities of the matching entry, deny aside.
  request_scope = {
    for code in local.owner_codes : code => concat(
      [
        { exact = false, value = "secret/data/${code}/", capabilities = ["create", "read", "update", "delete", "patch", "list"] },
        { exact = false, value = "secret/metadata/${code}/", capabilities = ["create", "read", "update", "delete", "list", "patch"] },
        { exact = false, value = "secret/delete/${code}/", capabilities = local.acl_capability.kv_version },
        { exact = false, value = "secret/destroy/${code}/", capabilities = local.acl_capability.kv_version },
        { exact = false, value = "sys/internal/ui/mounts/secret/", capabilities = local.acl_capability.read },
        { exact = true, value = "sys/auth", capabilities = local.acl_capability.read },
        { exact = false, value = "sys/auth/${code}-", capabilities = local.acl_capability.manage_mount },
        { exact = false, value = "sys/mounts/auth/${code}-", capabilities = local.acl_capability.configure },
        { exact = false, value = "auth/${code}-", capabilities = concat(local.acl_capability.manage, ["patch"]) },
        { exact = false, value = "auth/${local.approle_mount}/role/${code}-", capabilities = local.acl_capability.manage },
        { exact = false, value = "auth/${local.gitlab_mount}/role/${code}-", capabilities = local.acl_capability.manage },
        { exact = true, value = "sys/mounts/${local.pki_mount}", capabilities = local.acl_capability.read },
        { exact = false, value = "${local.pki_mount}/roles/${code}-", capabilities = local.acl_capability.manage },
        { exact = false, value = "${local.pki_mount}/issue/${code}-", capabilities = local.acl_capability.issue },
        { exact = false, value = "${local.pki_mount}/sign/${code}-", capabilities = local.acl_capability.issue },
        { exact = true, value = "auth/token/renew-self", capabilities = local.acl_capability.renew },
        { exact = true, value = "auth/token/lookup-self", capabilities = local.acl_capability.read },
      ],
      [
        for grant in lookup(local.acl_cross_tenant_grants, code, []) : {
          exact = true, value = grant.path, capabilities = local.acl_capability[grant.capability]
        }
      ],
    )
  }

  # A requested policy MUST NOT reach the request secret, or a workload could request policies for itself.
  request_forbidden_prefixes = {
    for code in local.owner_codes : code => [
      for kind in ["data", "metadata", "delete", "destroy"] : "${local.policy_request.mount}/${kind}/${local.policy_request.names[code]}"
    ]
  }
}
