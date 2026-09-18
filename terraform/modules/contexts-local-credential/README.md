# contexts-local-credential

## Section 1. Purpose

A Bastion Vault is a HashiCorp Vault instance which manages infrastructure secrets for the `csning1998-lab` group. A local credential context is a configuration object which supplies Bastion Vault connection parameters and state backend authentication data to a calling Terraform layer.

This module provides the single source of truth for the local credential context across every Terraform layer in `csning1998-lab`. A calling layer MUST NOT derive connection parameters independently. Every calling layer MUST consume connection parameters and authentication objects through the module outputs described in Section 2 Item C.

## Section 2. Interface

### Item A. Usage

```hcl
module "local_credential_contexts" {
  source  = "gitlab.com/csning1998-lab/contexts-local-credential/gitlab"
  version = "~> 0.1"
}

provider "vault" {
  alias        = "bastion"
  address      = module.local_credential_contexts.bastion_vault_config.endpoint
  ca_cert_file = module.local_credential_contexts.bastion_vault_config.ca_cert_path
}
```

A caller inside `parent-group-governance` MAY reference the module through the relative path `../../modules/contexts-local-credential`. The `foundation-vault-bastion` layer MUST reference the module through the relative path in accordance with the cycle constraint in Section 3 Item A.

### Item B. Inputs

#### Item B.1. Variable `bastion_vault_config`

The variable `bastion_vault_config` defines the connection attributes for the Bastion Vault endpoint.

| Field          | Type     | Default                   | Description                                             |
| -------------- | -------- | ------------------------- | ------------------------------------------------------- |
| `endpoint`     | `string` | `https://172.16.0.1:8200` | Network address of the Bastion Vault listener.          |
| `ca_cert_path` | `string` | `null`                    | File path to the Bastion Vault listener CA certificate. |
| `token_path`   | `string` | `null`                    | File path to the authentication token file.             |

A `null` value in `ca_cert_path` activates the dynamic certificate generation path described in Section 3 Item B. An explicit file path in `ca_cert_path` overrides dynamic certificate generation. A `null` value in `token_path` instructs the module to read the token file at `~/.vault-token`.

#### Item B.2. Variable `bastion_vault_state`

The variable `bastion_vault_state` defines the remote state coordinates for retrieving the live Bastion Vault CA certificate. A caller MUST override the default values when accessing a Bastion Vault managed by an external project.

| Field         | Type     | Default                       | Description                                                       |
| ------------- | -------- | ----------------------------- | ----------------------------------------------------------------- |
| `project_id`  | `number` | `86417732`                    | GitLab project identifier hosting the remote state.               |
| `state_name`  | `string` | `"foundation-vault-bastion"`  | Name of the Terraform state file in GitLab.                       |
| `output_name` | `string` | `"bastion_vault_ca_cert_pem"` | Name of the state output containing the CA certificate PEM bytes. |

Upon initial execution by each consumer, the following command MUST be executed to bootstrap, as provider configurations cannot reliably depend on resources created during the same `apply` operation.

```bash
terraform apply -target=module.local_credential_contexts.local_file.bastion_ca_cert
```

#### Item B.3. Variable `gitlab_ci_remote_state_read_token`

The variable `gitlab_ci_remote_state_read_token` supplies a GitLab Personal Access Token with `read_api` scope for CI pipeline execution. A CI runner MUST NOT use `CI_JOB_TOKEN` for state retrieval because the GitLab Terraform State API rejects `CI_JOB_TOKEN`.

A `null` value in `gitlab_ci_remote_state_read_token` instructs the module to read the OAuth token from `~/.terraform.d/credentials.tfrc.json`. The `foundation-vault-bastion` layer supplies an explicit file path in `bastion_vault_config.ca_cert_path`. Consequently, the `foundation-vault-bastion` layer MAY leave `gitlab_ci_remote_state_read_token` unset in all environments.

### Item C. Outputs

#### Item C.1. Output `bastion_vault_config`

The output `bastion_vault_config` exposes an object which contains the resolved endpoint address, CA certificate file path, and token file path.

#### Item C.2. Output `state_auth_gitlab_saas`

The output `state_auth_gitlab_saas` exposes a sensitive object which contains authentication credentials for the GitLab HTTP state backend. Consuming layers MUST pass this object to the `config` argument of `data "terraform_remote_state"` blocks.

## Section 3. Dynamic CA Certificate Architecture

### Item A. Constraints and Path Selection

The `hashicorp/vault` Terraform provider requires a local file path for the `ca_cert_file` argument. The provider schema does not accept inline PEM content.

A static certificate file MUST NOT be committed inside this module. A committed certificate becomes invalid when the Bastion Vault CA rotates. A caller pinned to a static module version continues trusting an expired certificate until an explicit version upgrade occurs.

The chosen path extracts the certificate dynamically from remote state during `terraform apply`. The `foundation-vault-bastion` layer maintains the authoritative certificate file at `vault/tls/ca.pem`. The `foundation-vault-bastion` layer exports the certificate PEM bytes through the state output defined by `bastion_vault_state.output_name`. The `local_file.bastion_ca_cert` resource in consuming layers writes the PEM bytes to `${path.cwd}/tls/bastion-ca.pem` on each execution.

### Item B. State Synchronization and Operational Cost

The `foundation-vault-bastion` layer MUST supply `bastion_vault_config.ca_cert_path` explicitly. An explicit file path disables the `data "terraform_remote_state" "foundation_vault_bastion"` data source inside this module. An unset file path causes the data source to query the unapplied state of `foundation-vault-bastion` during execution.

The cost of the chosen path comprises local file generation and remote state read latency. The `local_file.bastion_ca_cert` resource creates an untracked file at `${path.cwd}/tls/bastion-ca.pem` during execution. The `.gitignore` file of each consuming layer MUST list `${path.cwd}/tls/bastion-ca.pem`. Consuming layers MUST maintain network access to the GitLab Terraform State API during execution.
