
locals {
  anthropic_workspace_id = var.anthropic_federation == null ? null : (
    var.anthropic_federation.workspace_id != null ? var.anthropic_federation.workspace_id : (
      length(anthropic_workspace.this) > 0 ? anthropic_workspace.this[0].id : null
    )
  )

  anthropic_binding = var.anthropic_federation == null ? {} : {
    anthropic = {
      variables = {
        ANTHROPIC_FEDERATION_RULE_ID = anthropic_federation_rule.this[0].id
        ANTHROPIC_ORGANIZATION_ID    = var.anthropic_federation.organization_id
        ANTHROPIC_SERVICE_ACCOUNT_ID = anthropic_service_account.this[0].id
        ANTHROPIC_WORKSPACE_ID       = local.anthropic_workspace_id
      }
      document = {
        federation_rule_id = anthropic_federation_rule.this[0].id
        issuer_id          = var.anthropic_federation.issuer_id
        organization_id    = var.anthropic_federation.organization_id
        service_account_id = anthropic_service_account.this[0].id
        workspace_id       = local.anthropic_workspace_id
      }
    }
  }

  bindings = local.anthropic_binding

  ci_variables = merge([
    for provider_name, binding in local.bindings : {
      for var_name, var_value in binding.variables :
      "${provider_name}/${var_name}" => {
        key   = var_name
        value = var_value
      }
    }
  ]...)
}

resource "anthropic_workspace" "this" {
  count = var.anthropic_federation != null && var.anthropic_federation.workspace_id == null ? 1 : 0

  name = coalesce(var.anthropic_federation.workspace_name, "ws-${var.gitlab_project.code}")
}

resource "anthropic_service_account" "this" {
  count = var.anthropic_federation == null ? 0 : 1

  name              = "sa-project-${var.gitlab_project.code}"
  organization_role = var.anthropic_federation.organization_role
}

resource "anthropic_service_account_workspace" "this" {
  count = var.anthropic_federation == null ? 0 : 1

  service_account_id = anthropic_service_account.this[0].id
  workspace_id       = local.anthropic_workspace_id
  workspace_role     = "workspace_developer"
}

resource "anthropic_federation_rule" "this" {
  count = var.anthropic_federation == null ? 0 : 1

  name                   = "rule-project-${var.gitlab_project.code}"
  workspace_id           = local.anthropic_workspace_id
  issuer_id              = var.anthropic_federation.issuer_id
  oauth_scope            = var.anthropic_federation.oauth_scope
  token_lifetime_seconds = var.anthropic_federation.token_lifetime_seconds

  match = {
    subject_prefix = "project_path:${var.gitlab_project.path}:*"
    audience       = var.anthropic_federation.audience
  }

  target = {
    service_account_id = anthropic_service_account.this[0].id
  }
}

resource "gitlab_project_variable" "ci_variable" {
  for_each = local.ci_variables

  project   = tostring(var.gitlab_project.id)
  key       = each.value.key
  value     = each.value.value
  masked    = false
  hidden    = false
  raw       = true
  protected = false
}

resource "vault_kv_secret_v2" "binding" {
  for_each = local.bindings

  mount     = var.vault_kv_mount_path
  name      = "${var.gitlab_project.code}/workload-identity-federation/${each.key}"
  data_json = jsonencode(each.value.document)
}
