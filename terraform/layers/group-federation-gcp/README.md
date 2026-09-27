# Google Cloud Workload Identity Federation Layer Specification

This document defines the architecture, bootstrap procedure, credential lifecycle, and verification mechanisms for the `group-federation-gcp` layer.

## Section 1. Architecture Overview

### Item A. Layer Responsibility

The `group-federation-gcp` layer manages the root Google Cloud Workload Identity Federation (WIF) Pool, OIDC Provider, and core API enablement at the organization project level.

- The layer enables required foundational GCP APIs: `iam.googleapis.com`, `iamcredentials.googleapis.com`, `sts.googleapis.com`, `aiplatform.googleapis.com`, and `generativelanguage.googleapis.com`.
- The layer registers the root Workload Identity Pool `gitlab-pool` and OIDC Provider `gitlab-provider` pointing to `https://gitlab.com`.
- The layer publishes root project metadata, pool identifiers, and provider contracts via Terraform Remote State Outputs for downstream consumption.
- The layer does not provision downstream service accounts or IAM role bindings. Downstream isolation remains the sole responsibility of consuming project layers invoking `provisioner-workload-identity-federation`.

### Item B. Authentication Model

The Google Cloud Terraform provider authenticates using Application Default Credentials (ADC) managed by the Google Cloud CLI.

- The provider retrieves OAuth2 tokens in memory from the local ADC credentials file `~/.config/gcloud/application_default_credentials.json`.
- The layer consumes state backend credentials via environment variables or Bastion Vault token injection.
- The root layer does not write back any project-level WIF binding secrets into Vault, preserving strict multi-tenant boundary isolation.

## Section 2. Host Prerequisites

### Item A. Operator Role Requirements

Execution requires administrative access to the target Google Cloud project.

- The operator account requires `roles/serviceusage.serviceUsageAdmin` and `roles/iam.workloadIdentityPoolAdmin` (or `roles/owner`) within the target Google Cloud project.
- The operator environment configures GitLab HTTP backend authentication via `TF_HTTP_USERNAME` and `TF_HTTP_PASSWORD`.

### Item B. CLI Tooling

The Google Cloud CLI `gcloud` is required for interactive operator authentication and verification.

- The `gcloud` executable must be available on `PATH`.

### Item C. Variable Correspondence Mapping

The following table defines the correspondence between shell environment variables and Terraform variables in `terraform.tfvars`:

| Environment Variable                     | Terraform Variable                   | Default / Example Value | Description                        |
| :--------------------------------------- | :----------------------------------- | :---------------------- | :--------------------------------- |
| `GCP_PROJECT_ID`                         | `gcp_project_id`                     | `<gcp-project-id>`      | Target Google Cloud Project ID     |
| `GCP_WORKLOAD_IDENTITY_POOL_ID`          | `workload_identity_pool_id`          | `gitlab-pool`           | Workload Identity Pool ID          |
| `GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID` | `workload_identity_pool_provider_id` | `gitlab-provider`       | Workload Identity Pool Provider ID |

## Section 3. Initial Bootstrap Operations

### Step A. Authenticate with Google Cloud

The operator exports the target project and federation pool identifiers, and logs in interactively to establish user credentials and local Application Default Credentials (ADC).

```bash
export GCP_PROJECT_ID="<gcp-project-id>"
export GCP_WORKLOAD_IDENTITY_POOL_ID="gitlab-pool"
export GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID="gitlab-provider"

gcloud auth login
gcloud auth application-default login
gcloud config set project "${GCP_PROJECT_ID}"
```

### Step B. Export State Backend Credentials

The operator exports the HTTP state backend credentials from Bastion Vault.

```bash
export TF_HTTP_USERNAME='gitlab-ci-token'
export TF_HTTP_PASSWORD=$(VAULT_ADDR='https://172.16.0.1:8200' VAULT_CACERT="$HOME/GitLab/csning1998-lab/parent-group-governance/vault/tls/ca.pem" VAULT_TOKEN=$(cat $HOME/.vault-token) vault kv get -field=token secret/parent-group-governance/terraform/state-backend)
```

### Step C. Execute Terraform Layer Deployment

The operator initializes the Terraform layer and applies the root federation pool and provider.

```bash
cd terraform/layers/group-federation-gcp
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

- `project.id`: The Google Cloud project ID configured in `terraform.tfvars`.
- `project.number`: The numeric project number resolved by the project data source.
- `project.name`: The human-readable project display name.
- `pool.id`: The Workload Identity Pool ID `gitlab-pool`.
- `pool.name`: The full resource path of the pool.
- `provider.id`: The Workload Identity Pool Provider ID `gitlab-provider`.
- `provider.name`: The full resource path of the provider.

### Item B. External Console and CLI Validation

The operator validates pool and provider registration directly against Google Cloud IAM APIs.

```bash
gcloud iam workload-identity-pools describe "${GCP_WORKLOAD_IDENTITY_POOL_ID}" \
  --location=global \
  --project="${GCP_PROJECT_ID}" \
  --format="yaml(name,state,displayName)"
```

```bash
gcloud iam workload-identity-pools providers describe "${GCP_WORKLOAD_IDENTITY_POOL_PROVIDER_ID}" \
  --workload-identity-pool="${GCP_WORKLOAD_IDENTITY_POOL_ID}" \
  --location=global \
  --project="${GCP_PROJECT_ID}" \
  --format="yaml(name,state,displayName,oidc.issuerUri,attributeCondition,attributeMapping)"
```

- The reported pool displays status `state: ACTIVE`.
- The reported provider displays status `state: ACTIVE` with `oidc.issuerUri: https://gitlab.com` and `attributeCondition: assertion.namespace_path.startsWith("csning1998-lab")`.

### Item C. API Services Enablement Validation

The operator validates that required Google Cloud APIs are active on the project.

```bash
gcloud services list --enabled --project="${GCP_PROJECT_ID}" --filter="NAME:(iamcredentials.googleapis.com OR sts.googleapis.com OR aiplatform.googleapis.com OR generativelanguage.googleapis.com)"
```

### Item D. Downstream Consumption Validation

The operator validates that consuming layers can resolve the remote state.

```bash
cd ../meta-gitlab-project
terraform init
terraform plan
```

- The plan step reads `data.terraform_remote_state.group_federation_gcp`.
- The plan step resolves `project.id`, `pool.id`, and `provider.id` without state acquisition errors.

## Section 5. Credential Lifecycle and Maintenance

### Item A. Credential Refresh and Destruction Protection

- Local ADC credentials refresh automatically through the Google Cloud CLI helper.
- Destruction of `google_iam_workload_identity_pool.gitlab_saas` and `google_iam_workload_identity_pool_provider.gitlab_saas` carries `prevent_destroy = true` lifecycle protection to avoid invalidating downstream project federation bindings.
