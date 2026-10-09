
mock_provider "anthropic" {}
mock_provider "azuread" {
  mock_resource "azuread_application" {
    defaults = {
      id        = "/applications/00000000-0000-0000-0000-000000000001"
      client_id = "11111111-2222-3333-4444-555555555555"
    }
  }
  mock_resource "azuread_service_principal" {
    defaults = {
      id        = "00000000-0000-0000-0000-000000000002"
      object_id = "22222222-3333-4444-5555-666666666666"
    }
  }
  mock_resource "azuread_application_federated_identity_credential" {
    defaults = {
      id = "33333333-4444-5555-6666-777777777777"
    }
  }
}
mock_provider "azurerm" {}
mock_provider "gitlab" {}
mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/test-gcp-project/serviceAccounts/sa-p-example-app@test-gcp-project.iam.gserviceaccount.com"
      email = "sa-p-example-app@test-gcp-project.iam.gserviceaccount.com"
    }
  }
}

variables {
  gitlab_project = {
    id   = 1001
    path = "example-group/example-app"
    code = "example-app"
  }
}

run "disabled_provider_creates_nothing" {
  command = plan

  assert {
    condition     = length(anthropic_service_account.this) == 0 && length(anthropic_federation_rule.this) == 0 && length(google_service_account.this) == 0 && length(google_service_account_iam_member.this) == 0 && length(google_project_iam_member.roles) == 0 && length(azuread_application.this) == 0 && length(azuread_service_principal.this) == 0 && length(azuread_application_federated_identity_credential.this) == 0 && length(azurerm_role_assignment.roles) == 0
    error_message = "null provider objects must create no Anthropic, Google, or Azure resources"
  }

  assert {
    condition     = length(gitlab_project_variable.ci_variable) == 0 && length(output.federation_bindings) == 0
    error_message = "null provider objects must publish no variables and no binding"
  }
}

run "anthropic_trust_is_derived_from_the_project" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  assert {
    condition     = anthropic_service_account.this[0].name == "sa-project-example-app" && anthropic_service_account.this[0].organization_role == "developer"
    error_message = "the service account must be named after the project code with sa-project prefix and developer role"
  }

  assert {
    condition     = anthropic_service_account_workspace.this[0].workspace_id == "wrkspc_TESTWORKSPACE000000000"
    error_message = "the service account must be a member of the workspace of the rule"
  }

  assert {
    condition     = anthropic_federation_rule.this[0].name == "rule-project-example-app" && anthropic_federation_rule.this[0].match.subject_prefix == "project_path:example-group/example-app:*"
    error_message = "the rule must match the CI jobs of the project path only and use rule-project prefix"
  }

  assert {
    condition     = anthropic_federation_rule.this[0].match.audience == "https://api.anthropic.com"
    error_message = "the rule must require the Anthropic audience by default"
  }

  assert {
    condition     = anthropic_federation_rule.this[0].oauth_scope == "workspace:inference" && anthropic_federation_rule.this[0].token_lifetime_seconds == 600
    error_message = "the rule must default to the inference scope and a ten minute token lifetime"
  }

  assert {
    condition     = anthropic_federation_rule.this[0].issuer_id == "fdis_TESTISSUER0000000000" && anthropic_federation_rule.this[0].workspace_id == "wrkspc_TESTWORKSPACE000000000"
    error_message = "the rule must use the issuer and the workspace of the caller"
  }
}

run "two_projects_share_no_state" {
  command = plan

  variables {
    gitlab_project = {
      id   = 2002
      path = "example-group/other-app"
      code = "other-app"
    }
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  assert {
    condition     = anthropic_service_account.this[0].name == "sa-project-other-app" && anthropic_federation_rule.this[0].match.subject_prefix == "project_path:example-group/other-app:*"
    error_message = "every value must come from the caller, none from an earlier call"
  }
}

run "auto_creates_workspace_when_omitted" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
    }
  }

  assert {
    condition     = length(anthropic_workspace.this) == 1 && anthropic_workspace.this[0].name == "ws-example-app"
    error_message = "when workspace_id is omitted, an anthropic_workspace must be auto-created with ws- prefix"
  }
}

run "anthropic_identifiers_are_published" {
  command = apply

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  assert {
    condition = toset(keys(gitlab_project_variable.ci_variable)) == toset([
      "anthropic/ANTHROPIC_FEDERATION_RULE_ID",
      "anthropic/ANTHROPIC_ORGANIZATION_ID",
      "anthropic/ANTHROPIC_SERVICE_ACCOUNT_ID",
      "anthropic/ANTHROPIC_WORKSPACE_ID",
    ])
    error_message = "exactly the four ANTHROPIC variables must be published to the project"
  }

  assert {
    condition     = gitlab_project_variable.ci_variable["anthropic/ANTHROPIC_ORGANIZATION_ID"].value == "abcdef01-2345-4678-89ab-cdef01234567" && gitlab_project_variable.ci_variable["anthropic/ANTHROPIC_ORGANIZATION_ID"].masked == false
    error_message = "identifiers are not secrets and must not be masked"
  }


  assert {
    condition     = output.federation_bindings["anthropic"].organization_id == "abcdef01-2345-4678-89ab-cdef01234567"
    error_message = "the anthropic binding must carry the identifiers"
  }
}

run "rejects_invalid_organization_id" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "org_abcdef"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  expect_failures = [var.anthropic_federation]
}

run "rejects_invalid_workspace_id" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrk_TESTWORKSPACE"
    }
  }

  expect_failures = [var.anthropic_federation]
}

run "rejects_invalid_issuer_id" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  expect_failures = [var.anthropic_federation]
}

run "accepts_default_workspace_literal" {
  command = plan

  variables {
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "default"
    }
  }

  assert {
    condition     = anthropic_federation_rule.this[0].workspace_id == "default"
    error_message = "the default workspace literal must be accepted"
  }
}

run "google_trust_is_derived_from_the_project" {
  command = plan

  variables {
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "123456789012"
      pool_id        = "gitlab-pool"
      provider_id    = "gitlab-provider"
    }
  }

  assert {
    condition     = google_service_account.this[0].account_id == "sa-p-example-app" && google_service_account.this[0].project == "test-gcp-project"
    error_message = "the service account must be named after the project code with sa-p- prefix and target the specified project"
  }

  assert {
    condition     = google_service_account_iam_member.this[0].role == "roles/iam.workloadIdentityUser"
    error_message = "the service account IAM member must grant workloadIdentityUser role"
  }

  assert {
    condition     = google_service_account_iam_member.this[0].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab-pool/attribute.project_path/example-group/example-app"
    error_message = "the IAM member must target the project path under the workload identity pool"
  }
}

run "google_grants_project_iam_roles" {
  command = apply

  variables {
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "123456789012"
      pool_id        = "gitlab-pool"
      provider_id    = "gitlab-provider"
    }
  }

  assert {
    condition     = toset(keys(google_project_iam_member.roles)) == toset(["roles/aiplatform.user", "roles/serviceusage.serviceUsageConsumer"])
    error_message = "default project IAM roles must grant aiplatform.user and serviceusage.serviceUsageConsumer"
  }

  assert {
    condition     = google_project_iam_member.roles["roles/aiplatform.user"].member == "serviceAccount:sa-p-example-app@test-gcp-project.iam.gserviceaccount.com"
    error_message = "the project IAM member must target the service account email"
  }

  assert {
    condition     = google_project_iam_member.roles["roles/aiplatform.user"].role == "roles/aiplatform.user" && google_project_iam_member.roles["roles/serviceusage.serviceUsageConsumer"].role == "roles/serviceusage.serviceUsageConsumer"
    error_message = "the project IAM member roles must match the requested roles"
  }
}

run "google_two_projects_share_no_state" {
  command = plan

  variables {
    gitlab_project = {
      id   = 2002
      path = "example-group/other-app"
      code = "other-app"
    }
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "123456789012"
      pool_id        = "gitlab-pool"
      provider_id    = "gitlab-provider"
    }
  }

  assert {
    condition     = google_service_account.this[0].account_id == "sa-p-other-app" && google_service_account_iam_member.this[0].member == "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/gitlab-pool/attribute.project_path/example-group/other-app"
    error_message = "every Google value must come from the caller, none from an earlier call"
  }
}

run "google_identifiers_are_published" {
  command = apply

  variables {
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "123456789012"
      pool_id        = "gitlab-pool"
      provider_id    = "gitlab-provider"
    }
  }

  assert {
    condition     = contains(keys(gitlab_project_variable.ci_variable), "google/GCP_WORKLOAD_IDENTITY_PROVIDER") && contains(keys(gitlab_project_variable.ci_variable), "google/GCP_SERVICE_ACCOUNT") && contains(keys(gitlab_project_variable.ci_variable), "google/GCP_PROJECT_ID") && contains(keys(gitlab_project_variable.ci_variable), "google/GCP_PROJECT_NUMBER")
    error_message = "the required GCP variables must be published to the project"
  }

  assert {
    condition     = gitlab_project_variable.ci_variable["google/GCP_WORKLOAD_IDENTITY_PROVIDER"].value == "projects/123456789012/locations/global/workloadIdentityPools/gitlab-pool/providers/gitlab-provider" && gitlab_project_variable.ci_variable["google/GCP_WORKLOAD_IDENTITY_PROVIDER"].masked == false
    error_message = "the workload identity provider identifier must match the expected resource path and not be masked"
  }


  assert {
    condition     = output.federation_bindings["google"].project_id == "test-gcp-project" && output.federation_bindings["google"].pool_id == "gitlab-pool"
    error_message = "the google binding must carry the federation identifiers"
  }
}

run "rejects_invalid_google_project_number" {
  command = plan

  variables {
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "not-a-number"
      pool_id        = "gitlab-pool"
      provider_id    = "gitlab-provider"
    }
  }

  expect_failures = [var.google_federation]
}

run "rejects_invalid_google_pool_id" {
  command = plan

  variables {
    google_federation = {
      project_id     = "test-gcp-project"
      project_number = "123456789012"
      pool_id        = "INVALID_POOL!"
      provider_id    = "gitlab-provider"
    }
  }

  expect_failures = [var.google_federation]
}

run "azure_trust_is_derived_from_the_project" {
  command = plan

  variables {
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  assert {
    condition     = azuread_application.this[0].display_name == "app-project-example-app"
    error_message = "the Azure AD application display name must be app-project-example-app"
  }

  assert {
    condition     = azuread_application_federated_identity_credential.this[0].display_name == "fic-project-example-app" && azuread_application_federated_identity_credential.this[0].issuer == "https://gitlab.com" && azuread_application_federated_identity_credential.this[0].subject == "project_path:example-group/example-app:ref_type:branch:ref:main"
    error_message = "the federated identity credential must target GitLab SaaS and the main branch of the project path"
  }
}

run "azure_grants_openai_user_role" {
  command = apply

  variables {
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  assert {
    condition     = toset(keys(azurerm_role_assignment.roles)) == toset(["Cognitive Services OpenAI User"])
    error_message = "default role assignment must grant Cognitive Services OpenAI User"
  }

  assert {
    condition     = azurerm_role_assignment.roles["Cognitive Services OpenAI User"].scope == "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
    error_message = "the role assignment must scope to the target cognitive account"
  }
}

run "azure_two_projects_share_no_state" {
  command = plan

  variables {
    gitlab_project = {
      id   = 2002
      path = "example-group/other-app"
      code = "other-app"
    }
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  assert {
    condition     = azuread_application.this[0].display_name == "app-project-other-app" && azuread_application_federated_identity_credential.this[0].subject == "project_path:example-group/other-app:ref_type:branch:ref:main"
    error_message = "every Azure AD value must come from the caller, none from an earlier call"
  }
}

run "azure_identifiers_are_published" {
  command = apply

  variables {
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  assert {
    condition     = contains(keys(gitlab_project_variable.ci_variable), "azure/AZURE_TENANT_ID") && contains(keys(gitlab_project_variable.ci_variable), "azure/AZURE_CLIENT_ID") && contains(keys(gitlab_project_variable.ci_variable), "azure/AZURE_OPENAI_ENDPOINT") && contains(keys(gitlab_project_variable.ci_variable), "azure/AZURE_FEDERATED_CREDENTIAL_ID")
    error_message = "the required Azure variables must be published to the project"
  }

  assert {
    condition     = gitlab_project_variable.ci_variable["azure/AZURE_TENANT_ID"].value == "11111111-2222-3333-4444-555555555555" && gitlab_project_variable.ci_variable["azure/AZURE_TENANT_ID"].masked == false
    error_message = "azure tenant id must not be masked"
  }


  assert {
    condition     = output.federation_bindings["azure"].tenant_id == "11111111-2222-3333-4444-555555555555" && output.federation_bindings["azure"].openai_endpoint == "https://oai-test-account.openai.azure.com/"
    error_message = "the azure binding must carry the federation identifiers"
  }
}

run "rejects_invalid_azure_tenant_id" {
  command = plan

  variables {
    azure_federation = {
      tenant_id            = "invalid-uuid"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  expect_failures = [var.azure_federation]
}

run "rejects_invalid_azure_subscription_id" {
  command = plan

  variables {
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "invalid-sub-uuid"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "https://oai-test-account.openai.azure.com/"
    }
  }

  expect_failures = [var.azure_federation]
}

run "rejects_invalid_azure_openai_endpoint" {
  command = plan

  variables {
    azure_federation = {
      tenant_id            = "11111111-2222-3333-4444-555555555555"
      subscription_id      = "22222222-3333-4444-5555-666666666666"
      cognitive_account_id = "/subscriptions/22222222-3333-4444-5555-666666666666/resourceGroups/rg-test-azure/providers/Microsoft.CognitiveServices/accounts/oai-test-account"
      openai_endpoint      = "http://insecure-endpoint.openai.azure.com/"
    }
  }

  expect_failures = [var.azure_federation]
}
