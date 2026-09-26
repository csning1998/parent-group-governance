
mock_provider "anthropic" {}
mock_provider "gitlab" {}
mock_provider "vault" {}

variables {
  gitlab_project = {
    id   = 1001
    path = "csning1998-lab/example-app"
    code = "example-app"
  }
}

run "disabled_provider_creates_nothing" {
  command = plan

  assert {
    condition     = length(anthropic_service_account.this) == 0 && length(anthropic_federation_rule.this) == 0
    error_message = "a null anthropic object must create no Anthropic resources"
  }

  assert {
    condition     = length(gitlab_project_variable.ci_variable) == 0 && length(vault_kv_secret_v2.binding) == 0
    error_message = "a null anthropic object must publish no variables and no Vault document"
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
    condition     = anthropic_federation_rule.this[0].name == "rule-project-example-app" && anthropic_federation_rule.this[0].match.subject_prefix == "project_path:csning1998-lab/example-app:*"
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
      path = "csning1998-lab/other-app"
      code = "other-app"
    }
    anthropic_federation = {
      issuer_id       = "fdis_TESTISSUER0000000000"
      organization_id = "abcdef01-2345-4678-89ab-cdef01234567"
      workspace_id    = "wrkspc_TESTWORKSPACE000000000"
    }
  }

  assert {
    condition     = anthropic_service_account.this[0].name == "sa-project-other-app" && anthropic_federation_rule.this[0].match.subject_prefix == "project_path:csning1998-lab/other-app:*"
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
    condition     = vault_kv_secret_v2.binding["anthropic"].name == "example-app/workload-identity-federation/anthropic"
    error_message = "the Vault document must live under the project code and the provider name"
  }

  assert {
    condition     = jsondecode(vault_kv_secret_v2.binding["anthropic"].data_json).organization_id == "abcdef01-2345-4678-89ab-cdef01234567"
    error_message = "the Vault document must carry the identifiers"
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
