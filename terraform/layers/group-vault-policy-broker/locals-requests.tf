
locals {
  # The request document is not secret. Policy text carries paths and capabilities alone.
  requested = {
    for code in local.owner_codes : code => {
      for name, document in nonsensitive(data.vault_generic_secret.policy_request[code].data) : name => jsondecode(document)
    }
  }

  request_rules = flatten([
    for code in local.owner_codes : [
      for name, document in local.requested[code] : [
        for path, rule in try(document.path, {}) : {
          code         = code
          name         = name
          path         = path
          keys         = keys(rule)
          capabilities = try(tolist(rule.capabilities), [])
          # The literal part of a path ends at its first glob. A glob path covers every path which begins with the literal part.
          literal = split("*", split("+", path)[0])[0]
        }
      ]
    ]
  ])

  # Tenant ACL policy names belong to the broker, and every other name carries the owner code prefix.
  violations_name = flatten([
    for code in local.owner_codes : [
      for name in keys(local.requested[code]) : "${code}: policy name ${name} MUST begin with ${code}- and MUST differ from ${code}-terraform-operator"
      if !startswith(name, "${code}-") || name == "${code}-terraform-operator"
    ]
  ])

  violations_document = flatten([
    for code in local.owner_codes : [
      for name, document in local.requested[code] : "${code}/${name}: the document MUST hold the path object and MAY hold assignable_policies alone"
      if !can(keys(document.path)) || length(setsubtract(keys(document), ["path", "assignable_policies"])) > 0
    ]
  ])

  violations_rule = [
    for rule in local.request_rules : "${rule.code}/${rule.name}: ${rule.path} ${jsonencode(rule.capabilities)} lies outside the tenant scope"
    if !(
      length(rule.keys) == 1 && contains(rule.keys, "capabilities")
      && anytrue([
        for entry in local.request_scope[rule.code] :
        (entry.exact ? rule.path == entry.value : startswith(rule.path, entry.value))
        && length(setsubtract(rule.capabilities, concat(entry.capabilities, ["deny"]))) == 0
      ])
    )
  ]

  violations_request_secret = [
    for rule in local.request_rules : "${rule.code}/${rule.name}: ${rule.path} reaches the policy request secret"
    if anytrue([
      for forbidden in local.request_forbidden_prefixes[rule.code] :
      startswith(rule.path, forbidden) || (rule.literal != rule.path && startswith(forbidden, rule.literal))
    ]) && toset(rule.capabilities) != toset(["deny"])
  ]

  # A policy MAY let its holder assign only policies within the tenant ceiling.
  violations_assignable = flatten([
    for code in local.owner_codes : [
      for name, document in local.requested[code] : [
        for assignable in try(tolist(document.assignable_policies), []) : "${code}/${name}: assignable policy ${assignable} lies outside the tenant ceiling"
        if !contains(local.policy_ceiling[code], assignable)
      ]
    ]
  ])

  violations = concat(
    local.violations_name, local.violations_document, local.violations_rule, local.violations_request_secret, local.violations_assignable,
  )
}

# Exact names only. A glob such as <code>-* admits the comma separated string "<code>-a,other", which the auth method
# splits into two policies.
locals {
  policy_ceiling = {
    for code in local.owner_codes : code => concat(
      ["default"],
      sort([for name in keys(local.requested[code]) : name if startswith(name, "${code}-") && name != "${code}-terraform-operator"]),
      local.transit_unseal_policies[code],
      local.registry_reader_policies[code],
    )
  }

  # A transit unseal policy stays on the auth mounts of the tenant, which carry the Downstream Vault pod logins.
  # The shared scope drops every transit unseal policy, since the tenant chooses the role claims on the shared mounts.
  assignable_by_scope = {
    for code in local.owner_codes : code => {
      owned  = local.policy_ceiling[code]
      shared = [for policy in local.policy_ceiling[code] : policy if !contains(local.transit_unseal_policies[code], policy)]
    }
  }

  # The tenant ACL assigns any policy of the scope ceiling. A requested policy assigns only its declared assignable
  # policies within the scope. The operator of one component therefore cannot assign the policy of another.
  role_parameter_ceiling = {
    for code in local.owner_codes : code => {
      for scope, policies in local.assignable_by_scope[code] : scope => {
        "token_policies" = policies
        "policies"       = policies
        "*"              = []
      }
    }
  }

  role_parameter_assignable = {
    for code in local.owner_codes : code => {
      for name, document in local.requested[code] : name => {
        for scope, ceiling in local.assignable_by_scope[code] : scope => {
          "token_policies" = setintersection(ceiling, distinct(concat(["default"], try(tolist(document.assignable_policies), []))))
          "policies"       = setintersection(ceiling, distinct(concat(["default"], try(tolist(document.assignable_policies), []))))
          "*"              = []
        }
      }
    }
  }

  role_write_capabilities = ["create", "update", "patch"]

  tenant_acl_document = {
    for code in local.owner_codes : code => {
      path = merge([
        for category in local.acl_category_order : {
          for rule in local.acl_rules[code][category] : rule.path => merge(
            { capabilities = local.acl_capability[rule.capability] },
            [
              for restrict in [lookup(rule, "restrict_policies", false)] : {
                allowed_parameters = local.role_parameter_ceiling[code][startswith(rule.path, "auth/${code}-") ? "owned" : "shared"]
              } if restrict
            ]...
          )
        }
      ]...)
    }
  }

  brokered = merge([
    for code in local.owner_codes : {
      for name, document in local.requested[code] : name => {
        code = code
        document = {
          path = {
            for path, rule in document.path : path => merge(
              { capabilities = rule.capabilities },
              [
                for write in [length(setintersection(rule.capabilities, local.role_write_capabilities)) > 0] : {
                  allowed_parameters = local.role_parameter_assignable[code][name][startswith(path, "auth/${code}-") ? "owned" : "shared"]
                } if write && startswith(path, "auth/")
              ]...
            )
          }
        }
      }
    }
  ]...)
}
