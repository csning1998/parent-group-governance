# Microsoft Azure & Azure OpenAI Workload Identity Federation Layer Specification

This document defines the architecture, bootstrap procedure, credential lifecycle, and verification mechanisms for the `group-federation-azure` layer.

## Section 1. Architecture Overview

### Item A. Layer Responsibility

The `group-federation-azure` layer manages the root Microsoft Entra ID and Azure OpenAI Cognitive Services infrastructure at the organization subscription level.

- The layer provisions the foundation Azure Resource Group, the Azure OpenAI Cognitive Account, and the Key Vault.
- `is_premium_tier` defaults to false and keeps the free tier.
- The free tier keeps public HTTPS. A network ACL denies clients outside `key_vault_ip_rules`.
- The premium tier disables public network access and provisions a private endpoint.
- The cognitive account disables local authentication. Callers present Entra ID tokens.
- Encryption at rest uses a customer managed key in the layer Key Vault.
- The layer discovers Microsoft Entra ID tenant ID and Azure subscription metadata.
- The layer publishes root tenant, subscription, and Azure OpenAI endpoint contracts via Terraform Remote State Outputs for downstream consumption.
- The layer does not provision downstream application registrations, service principals, or federated identity credentials. Downstream isolation remains the sole responsibility of consuming project layers invoking `provisioner-workload-identity-federation`.

### Item B. Authentication Model

The AzureAD and AzureRM Terraform providers authenticate using Azure CLI credentials.

- The providers retrieve authentication tokens in memory from the local Azure CLI profile.
- The layer consumes state backend credentials via environment variables or Bastion Vault token injection.
- The root layer does not write back any project-level WIF binding secrets into Vault, preserving strict multi-tenant boundary isolation.

### Item C. Network Boundary

The free tier keeps public HTTPS and applies a network ACL.

- `is_premium_tier` false sets the cognitive account network ACL default action to Deny. The ACL permits addresses in `key_vault_ip_rules`.
- Callers present Entra ID tokens because the account disables local authentication.
- `is_premium_tier` true disables public network access and provisions a virtual network, a private endpoint, and private DNS.
- GitLab CI runners reach the free tier data plane over public HTTPS from the address in `key_vault_ip_rules`.

### Item D. Encryption at Rest

The cognitive account uses a customer managed key stored in the layer Key Vault.

- The user assigned managed identity of the cognitive account receives the Key Vault Crypto Service Encryption User role.
- The free tier uses the standard SKU and a software RSA key. The premium tier uses the premium SKU and an RSA-HSM key.
- The cognitive account restricts outbound network access to the account hostname and the Key Vault hostname.
- The Key Vault firewall denies data plane calls. The firewall permits Azure services and addresses in `key_vault_ip_rules`. The premium tier also permits the private endpoint subnet.
- `key_vault_ip_rules` must contain the workstation public egress address. The group GitLab runner uses the same address.

## Section 2. Host Prerequisites

### Item A. Operator Role Requirements

Execution requires administrative access to the target Microsoft Entra ID tenant and Azure subscription.

- The operator account requires `Contributor` or `Owner` role on the target Azure subscription.
- The operator account requires permission to assign roles on the Key Vault. The Owner role includes permission to assign roles. The Contributor role does not include permission to assign roles.
- The operator account requires `Application Administrator` or `Global Administrator` role in Microsoft Entra ID to create app registrations and service principals.
- The operator environment configures GitLab HTTP backend authentication via `TF_HTTP_USERNAME` and `TF_HTTP_PASSWORD`.

### Item B. CLI Tooling

The Azure CLI `az` is required for interactive operator authentication and verification.

- The operator can install `az` using the repository playbook `ansible/playbooks/workstation_cloud_cli.yaml`.
- The `az` executable must be available on `PATH`.

### Item C. Variable Correspondence Mapping

The following table defines the correspondence between shell environment variables and Terraform variables in `terraform.tfvars`:

| Environment Variable                   | Terraform Variable               | Default / Example Value   | Description                                               |
| :------------------------------------- | :------------------------------- | :------------------------ | :-------------------------------------------------------- |
| `AZURE_SUBSCRIPTION_ID`                | `azure_subscription_id`          | `<azure-subscription-id>` | Target Azure Subscription ID                              |
| `AZURE_TENANT_ID`                      | `azure_tenant_id`                | `<azure-tenant-id>`       | Target Microsoft Entra ID Tenant ID                       |
| `AZURE_RESOURCE_GROUP_NAME`            | `resource_group_name`            | `<resource-group-name>`   | Azure Resource Group name                                 |
| `AZURE_LOCATION`                       | `location`                       | `<location>`              | Azure deployment region                                   |
| `AZURE_COGNITIVE_ACCOUNT_NAME`         | `cognitive_account_name`         | `<openai-account-name>`   | Azure OpenAI Cognitive Services account name              |
| `AZURE_SKU_NAME`                       | `sku_name`                       | `S0`                      | Cognitive Services SKU tier                               |
| `AZURE_IS_PREMIUM_TIER`                | `is_premium_tier`                | `false`                   | Premium SKU, HSM key, and private endpoints               |
| `AZURE_VNET_ADDRESS_SPACE`             | `virtual_network_address_space`  | `["10.80.0.0/16"]`        | Address space of the layer virtual network                |
| `AZURE_PRIVATE_ENDPOINT_SUBNET_PREFIX` | `private_endpoint_subnet_prefix` | `10.80.0.0/24`            | Subnet prefix for private endpoints                       |
| `AZURE_KEY_VAULT_IP_RULES`             | `key_vault_ip_rules`             | `["203.0.113.10/32"]`     | Operator IPv4 CIDR blocks for Key Vault data plane access |
| `AZURE_CMK_EXPIRATION_DATE`            | `cmk_expiration_date`            | `2027-09-27T00:00:00Z`    | Expiration timestamp for the customer managed key         |

## Section 3. Initial Bootstrap Operations

### Step A. Authenticate with Azure

The operator exports the target subscription and resource identifiers, and logs in interactively to establish user credentials for Azure and Entra ID.

```bash
export AZURE_SUBSCRIPTION_ID="<azure-subscription-id>"
export AZURE_TENANT_ID="<azure-tenant-id>"
export AZURE_RESOURCE_GROUP_NAME="<resource-group-name>"
export AZURE_LOCATION="<location>"
export AZURE_COGNITIVE_ACCOUNT_NAME="<openai-account-name>"
export AZURE_SKU_NAME="S0"

az login --tenant "${AZURE_TENANT_ID}"
az account set --subscription "${AZURE_SUBSCRIPTION_ID}"
```

### Step B. Export State Backend Credentials

The operator exports the HTTP state backend credentials from Bastion Vault.

```bash
export TF_HTTP_USERNAME='gitlab-ci-token'
export TF_HTTP_PASSWORD=$(VAULT_ADDR='https://172.16.0.1:8200' VAULT_CACERT="$HOME/GitLab/csning1998-lab/parent-group-governance/vault/tls/ca.pem" VAULT_TOKEN=$(cat $HOME/.vault-token) vault kv get -field=token secret/parent-group-governance/terraform/state-backend)
```

### Step C. Execute Terraform Layer Deployment

The operator copies `terraform.tfvars.example` to `terraform.tfvars`. The operator leaves `is_premium_tier` false for the free tier. The operator replaces the documentation address in `key_vault_ip_rules` with the workstation public IPv4 CIDR. The group GitLab runner uses the same CIDR. The operator initializes the Terraform layer. The operator applies the configuration.

```bash
cd terraform/layers/group-federation-azure
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

- `tenant.id`: The Microsoft Entra ID tenant ID resolved by `azuread_client_config`.
- `subscription.id`: The Azure subscription ID resolved by `azurerm_client_config`.
- `resource_group.name`: The Azure Resource Group name hosting cognitive services.
- `openai.id`: The resource ID of the Azure OpenAI Cognitive Account.
- `openai.name`: The account name of the Azure OpenAI Cognitive Account.
- `openai.endpoint`: The HTTPS endpoint URL of the Azure OpenAI Cognitive Account. The premium tier resolves the hostname to the private endpoint through private DNS.
- `deployments`: Map of deployed model deployment IDs and names.
- `network.private_endpoint_id`: The resource ID of the cognitive account private endpoint. The value is null on the free tier.
- `encryption.key_vault_id`: The resource ID of the Key Vault.
- `encryption.key_id`: The versionless resource ID of the customer managed key.

### Item B. External Console and CLI Validation

The operator validates cognitive account registration directly against Azure CLI.

```bash
az cognitiveservices account show \
    --name "${AZURE_COGNITIVE_ACCOUNT_NAME}" \
    --resource-group "${AZURE_RESOURCE_GROUP_NAME}" \
    --output table
```

### Item C. Downstream Consumption Validation

The operator validates that consuming layers can resolve the remote state.

```bash
cd ../meta-gitlab-project
terraform init
terraform plan
```

- The plan step reads `data.terraform_remote_state.group_federation_azure`.
- The plan step resolves `tenant.id`, `subscription.id`, and `openai.endpoint` without state acquisition errors.

## Section 5. Credential Lifecycle and Maintenance

### Item A. Destruction Protection

- Destruction of `azurerm_resource_group.group_federation` and `azurerm_cognitive_account.openai` carries `prevent_destroy = true` lifecycle protection to avoid invalidating downstream project federation bindings.
- Destruction of `azurerm_key_vault.openai` and `azurerm_cognitive_account_customer_managed_key.openai` carries `prevent_destroy = true`.
- The operator must disable purge protection before removal of the Key Vault.
