# Anthropic Workload Identity Federation Layer Specification

This document defines the architecture, bootstrap procedure, credential lifecycle, and verification mechanisms for the `group-federation-anthropic` layer.

## Section 1. Architecture Overview

### Item A. Layer Responsibility

The `group-federation-anthropic` layer manages the root Anthropic Workload Identity Federation (WIF) OIDC trust issuer at the organization level.

- The layer registers the root OIDC trust issuer `issuer-gitlab-saas` pointing to `https://gitlab.com`.
- The layer publishes organization identifiers and issuer trust contracts via Terraform Remote State Outputs for downstream consumption.
- The layer does not provision downstream workspaces, service accounts, or federation rules. Multi-tenant project isolation is delegated to project layers invoking `provisioner-workload-identity-federation`.

### Item B. Ephemeral Credential Model

The Anthropic Terraform provider authenticates with two credentials read from Bastion Vault in memory.

- The Bastion Vault path `parent-group-governance/ai-provider-console/anthropic` holds two fields, and the operator owns both.

    | Vault field                    | Content                                                | Lifetime       | Provider argument |
    | ------------------------------ | ------------------------------------------------------ | -------------- | ----------------- |
    | `anthropic_admin_api_key`      | The Admin API key (`sk-ant-admin...`) from the Console | Until revoked  | `admin_api_key`   |
    | `anthropic_oauth_access_token` | The org:admin OAuth token of Section 3 Step A          | Within minutes | `auth_token`      |

- The provider builds one client per argument and never falls back from one client to the other, hence each field MUST hold its own credential type.

    | Provider argument | Client       | Header                  | Endpoints                                                   |
    | ----------------- | ------------ | ----------------------- | ----------------------------------------------------------- |
    | `admin_api_key`   | Admin client | `x-api-key`             | Workspaces, workspace members, the organization data source |
    | `auth_token`      | OAuth client | `authorization: Bearer` | Federation issuers, federation rules, service accounts      |

- The federation and service account endpoints reject an Admin API key for reads and for writes.
- The Admin API accepts an OAuth token in `authorization: Bearer` alone, hence an OAuth token in `anthropic_admin_api_key` MUST NOT be used.
- The provider does not refresh a token, hence the operator MUST write a fresh OAuth token immediately before each apply with `vault kv patch -method=rw`, which keeps the Admin API key.
- `ant auth print-credentials` refreshes the token of a logged in profile.
- The provider configuration takes precedence over the environment, hence `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_ADMIN_API_KEY` of the shell do not affect the layer.
- Sources:
    - [Manage WIF with the Admin API](https://platform.claude.com/docs/en/manage-claude/wif-admin-api)
    - [Admin API](https://platform.claude.com/docs/en/manage-claude/admin-api)
    - [`internal/admin/admin_client.go`](https://github.com/ippontech/terraform-provider-anthropic/blob/main/internal/admin/admin_client.go) of the provider, which sets `x-api-key`
    - The provider schema of `terraform providers schema -json` for `ippontech/anthropic` 1.43.5
- The layer declares the Vault secret datasource as `ephemeral`, preventing credential persistence inside Terraform state files.
- The root layer does not publish project-level WIF binding secrets back to Vault, preserving multi-tenant boundary isolation.

## Section 2. Host Prerequisites

### Item A. Operator Role Requirements

Execution requires interactive administrative access to the Anthropic organization.

- The operator account requires `org:admin`, `owner`, or `primary_owner` role within the targeted Anthropic organization.
- Bastion Vault must be unsealed with the KV version 2 secrets engine enabled at mount path `secret`.
- The operator environment configures GitLab HTTP backend authentication via `TF_HTTP_USERNAME` and `TF_HTTP_PASSWORD`.

### Item B. CLI Tooling

The Anthropic CLI `ant` is required for interactive operator authentication.

- The operator can install `ant` using the repository playbook `ansible/playbooks/workstation_cloud_cli.yaml`.
- The `ant` executable must be available on `PATH`.

```bash
cd ansible && ansible-playbook playbooks/workstation_cloud_cli.yaml --ask-become-pass && cd -
```

## Section 3. Initial Bootstrap Operations

### Step A. Authenticate with Anthropic Console

The operator exports the profile name and logs in interactively to mint a short-lived OAuth administrator token.

```bash
export ANTHROPIC_PROFILE="issuer-gitlab-saas"

ant auth login --profile "${ANTHROPIC_PROFILE}" --scope "org:admin"
```

### Step B. Commit Credential to Bastion Vault and Export Backend Credentials

The operator writes the credentials to Bastion Vault through the `administrator` identity with the HTTP state backend credentials exported.

1. The operator creates an Admin API key on the Admin API Keys page of the Console and writes the key once. The command reads the key from stdin, hence the key does not enter the shell history.

    ```bash
    eval "$(vault-proxy-env administrator)"
    printf 'Admin API key: ' && read -rs anthropic_key && echo
    printf '%s' "$anthropic_key" | vault kv put -mount=secret parent-group-governance/ai-provider-console/anthropic \
        anthropic_admin_api_key=-
    ```

2. The operator writes a fresh OAuth token immediately before each apply. The read and write method of `vault kv patch` keeps the Admin API key, since the identity policy grants no `patch` capability. The token reaches `vault` through stdin without its trailing newline, since other local users can read an argument through `/proc/<pid>/cmdline`, and `key=-` stores stdin verbatim.

    ```bash
    eval "$(vault-proxy-env administrator)"
    ant auth print-credentials --profile "${ANTHROPIC_PROFILE}" --access-token | tr -d '\n' | \
        vault kv patch -mount=secret -method=rw parent-group-governance/ai-provider-console/anthropic \
            anthropic_oauth_access_token=-
    ```

### Step C. Execute Terraform Layer Deployment

The operator initializes the Terraform layer and applies the root federation issuer.

```bash
cd terraform/layers/group-federation-anthropic
terraform init
terraform plan
terraform apply
```

## Section 4. Verification Procedures

### Item A. Remote State Outputs Verification

The operator inspects the published outputs to confirm state publication.

```bash
terraform output
```

The output contains the following structures:

- `organization.id`: The UUID of the current Anthropic organization.
- `organization.name`: The human-readable display name of the Anthropic organization.
- `issuers.gitlab_saas.id`: The unique issuer ID generated by Anthropic (prefixed with `fdis_`).
- `issuers.gitlab_saas.issuer_url`: The exact URL `https://gitlab.com`.
- `issuers.gitlab_saas.name`: The registered identifier `issuer-gitlab-saas`.

### Item B. External Console and CLI Validation

The operator validates issuer registration directly against the Anthropic API.

```bash
ant federation issuers list --profile "${ANTHROPIC_PROFILE}"
```

- The reported issuer list displays an entry matching the Terraform output `issuers.gitlab_saas.id`.
- The matching entry displays status `active` with OpenID Connect discovery pointing to `https://gitlab.com`.

### Item C. Downstream Consumption Validation

The operator validates that consuming layers can resolve the remote state.

```bash
cd ../administration-gitlab-project
terraform init
terraform plan
```

- The plan step reads `data.terraform_remote_state.group_federation_anthropic`.
- The plan step resolves `organization.id` and `issuers.gitlab_saas.id` without state acquisition errors.

## Section 5. Credential Lifecycle and Maintenance

### Item A. Re-Authentication Requirement

The temporary token generated by `ant auth login` carries a validity lifetime of minutes.

- When executing subsequent `terraform plan` or `terraform apply` runs against this layer, the operator MUST repeat Section 3 Step A and Step B to refresh the ephemeral Vault token.
- The resource `anthropic_federation_issuer.gitlab_saas` declares `prevent_destroy = true` lifecycle protection to prevent accidental revocation of downstream project federation rules.
