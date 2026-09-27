
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

  azure_subjects = var.azure_federation == null ? [] : coalesce(
    var.azure_federation.subjects,
    ["project_path:${var.gitlab_project.path}:ref_type:branch:ref:main"]
  )

  azure_binding = var.azure_federation == null ? {} : {
    azure = {
      variables = {
        AZURE_CLIENT_ID               = azuread_application.this[0].client_id
        AZURE_FEDERATED_CREDENTIAL_ID = azuread_application_federated_identity_credential.this[0].id
        AZURE_OPENAI_ENDPOINT         = var.azure_federation.openai_endpoint
        AZURE_TENANT_ID               = var.azure_federation.tenant_id
      }
      document = {
        client_id               = azuread_application.this[0].client_id
        cognitive_account_id    = var.azure_federation.cognitive_account_id
        federated_credential_id = azuread_application_federated_identity_credential.this[0].id
        openai_endpoint         = var.azure_federation.openai_endpoint
        service_principal_id    = azuread_service_principal.this[0].object_id
        subscription_id         = var.azure_federation.subscription_id
        tenant_id               = var.azure_federation.tenant_id
      }
    }
  }

  google_workload_identity_provider = var.google_federation == null ? null : "projects/${var.google_federation.project_number}/locations/global/workloadIdentityPools/${var.google_federation.pool_id}/providers/${var.google_federation.provider_id}"

  google_binding = var.google_federation == null ? {} : {
    google = {
      variables = {
        GCP_PROJECT_ID                 = var.google_federation.project_id
        GCP_PROJECT_NUMBER             = var.google_federation.project_number
        GCP_SERVICE_ACCOUNT            = google_service_account.this[0].email
        GCP_WORKLOAD_IDENTITY_PROVIDER = local.google_workload_identity_provider
      }
      document = {
        pool_id                    = var.google_federation.pool_id
        project_id                 = var.google_federation.project_id
        project_number             = var.google_federation.project_number
        provider_id                = var.google_federation.provider_id
        service_account_email      = google_service_account.this[0].email
        service_account_id         = google_service_account.this[0].id
        workload_identity_provider = local.google_workload_identity_provider
      }
    }
  }

  bindings = merge(
    local.anthropic_binding,
    local.azure_binding,
    local.google_binding,
  )

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

resource "azuread_application" "this" {
  count = var.azure_federation == null ? 0 : 1

  display_name = coalesce(var.azure_federation.application_name, "app-project-${var.gitlab_project.code}")
}

resource "azuread_service_principal" "this" {
  count = var.azure_federation == null ? 0 : 1

  client_id = azuread_application.this[0].client_id
}

resource "azuread_application_federated_identity_credential" "this" {
  count = length(local.azure_subjects)

  application_id = azuread_application.this[0].id
  display_name   = count.index == 0 ? "fic-project-${var.gitlab_project.code}" : substr("fic-${var.gitlab_project.code}-${count.index}", 0, 120)
  description    = "GitLab SaaS Workload Identity Federation for ${local.azure_subjects[count.index]}"
  audiences      = var.azure_federation.audiences
  issuer         = "https://gitlab.com"
  subject        = local.azure_subjects[count.index]
}

resource "azurerm_role_assignment" "roles" {
  for_each = var.azure_federation == null ? toset([]) : toset(var.azure_federation.roles)

  scope                = var.azure_federation.cognitive_account_id
  role_definition_name = each.value
  principal_id         = azuread_service_principal.this[0].object_id
}

resource "google_service_account" "this" {
  count = var.google_federation == null ? 0 : 1

  account_id   = coalesce(var.google_federation.service_account_id, substr("sa-p-${var.gitlab_project.code}", 0, 30))
  project      = var.google_federation.project_id
  display_name = "Service Account for GitLab project ${var.gitlab_project.code}"
}

resource "google_service_account_iam_member" "this" {
  count = var.google_federation == null ? 0 : 1

  service_account_id = google_service_account.this[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/${var.google_federation.project_number}/locations/global/workloadIdentityPools/${var.google_federation.pool_id}/attribute.project_path/${var.gitlab_project.path}"
}

resource "google_project_iam_member" "roles" {
  for_each = var.google_federation == null ? toset([]) : toset(var.google_federation.roles)

  project = var.google_federation.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.this[0].email}"
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
