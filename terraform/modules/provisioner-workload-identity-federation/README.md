# provisioner-workload-identity-federation

## Section 1. Purpose

Workload Identity Federation is a cryptographic identity exchange mechanism which authorizes GitLab CI/CD pipelines to access cloud provider APIs without static credentials. A workload federation provisioner is a Terraform module which registers per-project federated identities, assigns least-privilege cloud access roles, publishes pipeline environment variables, and records federation contract documents in Bastion Vault.

This module provides the authoritative implementation for provisioning multi-cloud Workload Identity Federation across `csning1998-lab` projects. Every consuming project layer MUST invoke this module to establish identity federation bindings for Anthropic, Google Cloud Platform, and Microsoft Azure OpenAI.

## Section 2. Interface

### Item A. Usage

```hcl
module "workload_identity_federation" {
  source  = "gitlab.com/csning1998-lab/provisioner-workload-identity-federation/gitlab"
  version = "~> 0.3.0"

  providers = {
    vault = vault.bastion
  }

  gitlab_project = {
    id   = module.baseline.project_id
    path = module.baseline.full_path
    code = var.gitlab_project_name
  }

  anthropic_federation = {
    issuer_id       = data.terraform_remote_state.group_federation_anthropic.outputs.issuers.gitlab_saas.id
    organization_id = data.terraform_remote_state.group_federation_anthropic.outputs.organization.id
  }

  google_federation = {
    project_id     = data.terraform_remote_state.group_federation_gcp.outputs.project.id
    project_number = data.terraform_remote_state.group_federation_gcp.outputs.project.number
    pool_id        = data.terraform_remote_state.group_federation_gcp.outputs.pool.id
    provider_id    = data.terraform_remote_state.group_federation_gcp.outputs.provider.id
  }

  azure_federation = {
    tenant_id            = data.terraform_remote_state.group_federation_azure.outputs.tenant.id
    subscription_id      = data.terraform_remote_state.group_federation_azure.outputs.subscription.id
    cognitive_account_id = data.terraform_remote_state.group_federation_azure.outputs.openai.id
    openai_endpoint      = data.terraform_remote_state.group_federation_azure.outputs.openai.endpoint
    subjects = [
      "project_path:${module.baseline.full_path}:ref_type:branch:ref:main",
    ]
  }
}
```

A caller inside `parent-group-governance` MAY reference this module through the relative path `../../modules/provisioner-workload-identity-federation`.

### Item B. Inputs

#### Item B.1. Variable `gitlab_project`

The variable `gitlab_project` defines target GitLab project metadata for workload identity federation bindings.

| Field  | Type     | Description                                          |
| ------ | -------- | ---------------------------------------------------- |
| `id`   | `number` | GitLab project numeric identifier.                   |
| `path` | `string` | Full path of the project including parent namespace. |
| `code` | `string` | Canonical project short identifier.                  |

#### Item B.2. Variable `anthropic_federation`

The variable `anthropic_federation` defines the federation configuration for the Anthropic Claude API.

| Field                    | Type               | Default                       | Description                                         |
| ------------------------ | ------------------ | ----------------------------- | --------------------------------------------------- |
| `issuer_id`              | `string`           | required                      | Identifier of the registered Anthropic OIDC issuer. |
| `organization_id`        | `string`           | required                      | UUID of the Anthropic organization.                 |
| `workspace_id`           | `optional(string)` | `null`                        | Existing Anthropic workspace ID (`wrkspc_*`).       |
| `workspace_name`         | `optional(string)` | `null`                        | Custom name when creating a dedicated workspace.    |
| `audience`               | `optional(string)` | `"https://api.anthropic.com"` | Target audience claim expected by Anthropic.        |
| `oauth_scope`            | `optional(string)` | `"workspace:inference"`       | Permitted OAuth scope for federated tokens.         |
| `token_lifetime_seconds` | `optional(number)` | `600`                         | Lifetime of federated access tokens in seconds.     |
| `organization_role`      | `optional(string)` | `"developer"`                 | Role assigned to the provisioned service account.   |

#### Item B.3. Variable `google_federation`

The variable `google_federation` defines the federation configuration for Google Cloud Platform.

| Field                | Type                     | Default                                                                | Description                                   |
| -------------------- | ------------------------ | ---------------------------------------------------------------------- | --------------------------------------------- |
| `project_id`         | `string`                 | required                                                               | Target GCP project ID.                        |
| `project_number`     | `string`                 | required                                                               | Numeric identifier of the target GCP project. |
| `pool_id`            | `string`                 | required                                                               | Workload Identity Pool identifier.            |
| `provider_id`        | `string`                 | required                                                               | Workload Identity Pool Provider identifier.   |
| `service_account_id` | `optional(string)`       | `null`                                                                 | Custom service account ID (defaults to code). |
| `roles`              | `optional(list(string))` | `["roles/aiplatform.user", "roles/serviceusage.serviceUsageConsumer"]` | IAM roles assigned to the service account.    |

#### Item B.4. Variable `azure_federation`

The variable `azure_federation` defines the federation configuration for Microsoft Azure and Azure OpenAI.

| Field                  | Type                     | Default                                     | Description                                         |
| ---------------------- | ------------------------ | ------------------------------------------- | --------------------------------------------------- |
| `tenant_id`            | `string`                 | required                                    | Microsoft Entra ID tenant UUID.                     |
| `subscription_id`      | `string`                 | required                                    | Azure subscription UUID.                            |
| `cognitive_account_id` | `string`                 | required                                    | Resource ID of the target Cognitive Account.        |
| `openai_endpoint`      | `string`                 | required                                    | HTTPS URL of the Azure OpenAI endpoint.             |
| `application_name`     | `optional(string)`       | `null`                                      | Custom display name for the Entra ID application.   |
| `audiences`            | `optional(list(string))` | `["https://gitlab.com"]`                    | Audiences accepted by the federated credential.     |
| `subjects`             | `optional(list(string))` | `["project_path:<path>:ref_type:...:main"]` | List of permitted subject assertion strings.        |
| `roles`                | `optional(list(string))` | `["Cognitive Services OpenAI User"]`        | Role definitions assigned to the service principal. |

#### Item B.5. Variable `vault_kv_mount_path`

The variable `vault_kv_mount_path` defines the mount path of the KV-v2 secrets engine in Bastion Vault. The default value is `"secret"`.

### Item C. Outputs

The module publishes the following outputs:

- `federation_bindings`: Map of active provider federation document objects.
- `anthropic_federation`: Resolved Anthropic federation metadata when enabled.
- `azure_federation`: Resolved Microsoft Azure federation metadata when enabled.
- `google_federation`: Resolved Google Cloud federation metadata when enabled.

## Section 3. Prerequisites and Operational Contracts

### Item A. Anthropic Federation Prerequisites

The `group-federation-anthropic` layer MUST be applied prior to consuming Anthropic federation. The `group-federation-anthropic` layer registers the organization-level OIDC issuer for GitLab SaaS (`https://gitlab.com`).

The Terraform operator executing this module MUST configure valid credentials for the `ippontech/anthropic` provider:

- `ANTHROPIC_ADMIN_API_KEY`: Organization administrator API key with authority to manage workspaces and service accounts.
- `ANTHROPIC_AUTH_TOKEN`: OAuth access token acquired through `ant auth login` possessing `org:admin` scope.

The module provisions a dedicated workspace `ws-<project_code>` when `workspace_id` is omitted. The module binds an `anthropic_federation_rule` matching the assertion subject prefix `project_path:${var.gitlab_project.path}:*`.

### Item B. Google Cloud Platform Prerequisites

The `group-federation-gcp` layer MUST be applied prior to consuming Google Cloud federation. The `group-federation-gcp` layer provisions the Workload Identity Pool and Workload Identity Provider. The target GCP project MUST have the following APIs enabled:

- `iam.googleapis.com`
- `iamcredentials.googleapis.com`
- `sts.googleapis.com`
- `aiplatform.googleapis.com`
- `generativelanguage.googleapis.com`

The Workload Identity Provider attribute mapping MUST map `attribute.project_path` to `assertion.project_path`.

The Terraform operator MUST possess IAM permissions to create service accounts and grant project-level role bindings in the target GCP project.

The module provisions a dedicated service account `sa-p-<project_code>` and grants `roles/iam.workloadIdentityUser` restricted to `principalSet://iam.googleapis.com/projects/<project_number>/locations/global/workloadIdentityPools/<pool_id>/attribute.project_path/<project_path>`.

### Item C. Microsoft Azure Prerequisites

The `group-federation-azure` layer MUST be applied prior to consuming Microsoft Azure federation. The `group-federation-azure` layer provisions the target Azure OpenAI Cognitive Account.

The Terraform operator MUST possess permissions to create Microsoft Entra ID Applications and assign Azure Role-Based Access Control (RBAC) roles:

- Microsoft Entra ID role: `Application Administrator` or `Cloud Application Administrator`.
- Azure Subscription role: `User Access Administrator` or `Role Based Access Control Administrator` scoped to the Cognitive Account resource group.

The module provisions a Microsoft Entra ID application, a service principal, and federated identity credentials. When `azure_federation.subjects` is not specified, the module provisions a credential restricted to the `main` branch.

### Item D. Bastion Vault and GitLab CI Operational Contracts

The consuming layer MUST configure a `vault` provider alias pointing to Bastion Vault. The module writes a federation document to `${var.vault_kv_mount_path}/${var.gitlab_project.code}/workload-identity-federation/<provider>` for each enabled provider.

The module provisions non-sensitive CI/CD project variables in GitLab for each enabled provider:

- Anthropic 4-tuple: `ANTHROPIC_FEDERATION_RULE_ID`, `ANTHROPIC_ORGANIZATION_ID`, `ANTHROPIC_SERVICE_ACCOUNT_ID`, `ANTHROPIC_WORKSPACE_ID`.
- Google Cloud 4-tuple: `GCP_PROJECT_ID`, `GCP_PROJECT_NUMBER`, `GCP_SERVICE_ACCOUNT`, `GCP_WORKLOAD_IDENTITY_PROVIDER`.
- Microsoft Azure 4-tuple: `AZURE_CLIENT_ID`, `AZURE_FEDERATED_CREDENTIAL_ID`, `AZURE_OPENAI_ENDPOINT`, `AZURE_TENANT_ID`.

GitLab CI runner jobs use these variables to request OIDC `id_tokens` and exchange tokens with cloud providers dynamically without static secrets.
