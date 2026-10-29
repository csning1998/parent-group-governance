# Microsoft Azure & Azure OpenAI Organization Layer Specification

This document defines the architecture, bootstrap procedure, credential lifecycle, and verification mechanisms for the `group-ai-provider-azure` layer.

## Section 1. Architecture Overview

### Item A. Layer Responsibility

The `group-ai-provider-azure` layer manages the root Microsoft Entra ID and Azure OpenAI Cognitive Services infrastructure at the organization subscription level.

- The layer provisions the foundation Azure Resource Group, the Azure OpenAI Cognitive Account, and the Key Vault instance.
- The input variable `is_premium_tier` defaults to false to maintain the Standard tier.
- The Standard tier keeps public HTTPS access enabled because the Standard tier does not provision private endpoints.
- A network ACL restricts cognitive account ingress by denying client traffic originating outside the IP addresses configured in `key_vault_ip_rules`.
- Setting `is_premium_tier` to true disables public network access on the cognitive service account.
- The Premium tier provisions an Azure Virtual Network, private DNS zones, and private endpoints for secure internal network ingress.
- The cognitive account disables local key authentication to enforce centralized access management.
- All client applications must authenticate by presenting Microsoft Entra ID OAuth tokens.
- Encryption at rest relies on a customer managed key stored in the layer Key Vault.
- Terraform data sources dynamically discover the Microsoft Entra ID tenant identifier and Azure subscription metadata from the authenticated operator session.
- The layer exposes the tenant ID, subscription ID, resource group name, and OpenAI endpoint URL through Terraform remote state outputs for the governance layer of this repository.
- The layer publishes `tenant_id`, `subscription_id`, `cognitive_account_id`, and `openai_endpoint` at `registry/platform/ai-provider/azure` of the Bastion Vault for the governance layers of other repositories, which read no state of this project.
- The root layer does not provision project level application registrations, service principals, or federated identity credentials.
- Consuming project layers maintain sole responsibility for provisioning downstream identity federation by invoking `provisioner-workload-identity-federation`.
- This division of responsibility preserves strict tenant isolation across project boundaries.

### Item B. Authentication Model

The AzureAD and AzureRM Terraform providers authenticate by consuming local Azure CLI credentials.

- The Terraform providers acquire OAuth authentication tokens in memory from the active Azure CLI user profile.
- This token acquisition mechanism avoids storing long lived cloud service principal credentials on the operator workstation.
- The layer retrieves remote state backend credentials through environment variables or Bastion Vault token injection.
- The Vault provider writes the registry key through the `administrator` Proxy, which `eval "$(vault-proxy-env administrator)"` loads.
- The root layer does not store project level Workload Identity Federation credentials in Vault.
- This boundary maintains strict multi-tenant security isolation across independent downstream projects.

### Item C. Network Boundary

The network topology provides two distinct security tiers controlled by the `is_premium_tier` variable.

- In the Standard tier, public network access remains active over HTTPS because the Standard tier does not provision private endpoints.
- The cognitive account network ACL assigns a default action of Deny to all external traffic.
- The network ACL permits incoming requests exclusively from the public IPv4 addresses specified in `key_vault_ip_rules`.
- The cognitive account ACL configuration strips single host `/32` CIDR masks because the Azure Cognitive Services API rejects prefix notation on individual IP rules.
- GitLab CI runners and operator workstations communicate with the Standard tier data plane over public HTTPS from the authorized egress addresses defined in `key_vault_ip_rules`.
- All callers must authenticate by supplying Microsoft Entra ID tokens because the cognitive service account disables local API keys.
- In the Premium tier, setting `is_premium_tier` to true disables public network access on both the cognitive account and the Key Vault.
- The Premium tier configuration provisions a dedicated Azure Virtual Network alongside a private endpoint subnet.
- Private endpoints link the cognitive account and the Key Vault directly to the private subnet through Azure Private Link.
- Private DNS zones for `privatelink.openai.azure.com` and `privatelink.vaultcore.azure.net` attach to the virtual network.
- The private DNS zones resolve service hostnames to internal private IP addresses for secure internal communication.

### Item D. Encryption at Rest

The Azure OpenAI cognitive account encrypts all data at rest using a customer managed key stored in the layer Key Vault.

- Terraform provisions a dedicated User Assigned Managed Identity for the cognitive account.
- The managed identity receives the Key Vault Crypto Service Encryption User role assignment on the Key Vault scope.
- This role assignment grants the managed identity permission to execute `wrapKey` and `unwrapKey` cryptographic operations.
- The Standard tier deploys the `standard` Key Vault SKU and generates a software protected 2048 bit RSA key to minimize deployment expenses.
- The Premium tier deploys the `premium` Key Vault SKU and generates an RSA-HSM hardware protected key to satisfy enterprise compliance requirements.
- The cognitive account enables outbound network access restrictions to prevent data exfiltration.
- Outbound network routing permits egress traffic only to the cognitive account hostname and the Key Vault hostname.
- The Key Vault firewall enforces a default Deny policy against all data plane calls.
- The Key Vault firewall permits trusted Azure services through the service bypass configuration.
- The Key Vault firewall permits incoming connections from operator workstations and GitLab runners matching `key_vault_ip_rules`.
- The Premium tier configuration additionally permits traffic from the private endpoint subnet.
- The variable `key_vault_ip_rules` must contain the public egress IPv4 address of the operator workstation.
- The group GitLab CI runner shares this same public egress address to maintain administrative and deployment access.

## Section 2. Host Prerequisites

### Item A. Operator Role Requirements

Layer deployment requires administrative privileges across both the Azure subscription and the Microsoft Entra ID tenant.

- The operator account requires the `Contributor` or `Owner` role on the target Azure subscription to create foundational resources.
- The operator account requires explicit role assignment permissions on the Key Vault scope.
- The subscription `Owner` role inherently includes permission to manage role assignments.
- The subscription `Contributor` role does not grant role assignment authority.
- An operator holding only `Contributor` status must obtain an additional role, such as `User Access Administrator` or `Role Based Access Control Administrator`.
- The layer does not create Microsoft Entra ID applications, hence the operator does not require a Microsoft Entra ID administrative role.
- The operator shell environment requires valid GitLab HTTP backend credentials stored in `TF_HTTP_USERNAME` and `TF_HTTP_PASSWORD`.

### Item B. CLI Tooling

The Azure CLI toolchain `az` is required for operator authentication and deployment verification.

- Operators can install the `az` utility by executing the repository Ansible playbook `ansible/playbooks/workstation_cloud_cli.yaml`.
- The `az` executable must reside in a directory registered on the system `PATH` environment variable.

### Item C. Terraform Variables

The following table lists the Terraform variables in `terraform.tfvars`.
Terraform does not read the `AZURE_*` shell variables of Section 3 Step A, which serve the Azure CLI commands alone.

| Terraform Variable               | Default / Example Value   | Description                                                                |
| :------------------------------- | :------------------------ | :------------------------------------------------------------------------- |
| `azure_subscription_id`          | `<azure-subscription-id>` | Target Azure subscription identifier hosting the cognitive services layer  |
| `azure_tenant_id`                | `<azure-tenant-id>`       | Target Microsoft Entra ID directory tenant identifier                      |
| `resource_group_name`            | `<resource-group-name>`   | Name of the Azure Resource Group hosting OpenAI and Key Vault resources    |
| `location`                       | `<location>`              | Azure geographical region selected for resource deployment                 |
| `cognitive_account_name`         | `<openai-account-name>`   | Globally unique account name for Azure OpenAI Cognitive Services           |
| `sku_name`                       | `S0`                      | Pricing and capacity SKU tier for Cognitive Services                       |
| `is_premium_tier`                | `false`                   | Toggle enabling premium Key Vault SKU, HSM key, and private endpoints      |
| `virtual_network_address_space`  | `["10.80.0.0/16"]`        | IPv4 address space allocated to the private endpoint virtual network       |
| `private_endpoint_subnet_prefix` | `10.80.0.0/24`            | Subnet CIDR block hosting private endpoints within the virtual network     |
| `key_vault_ip_rules`             | `["203.0.113.10/32"]`     | Operator IPv4 addresses or CIDR blocks permitted for Key Vault data access |
| `cmk_expiration_date`            | `2027-09-27T00:00:00Z`    | RFC 3339 UTC expiration timestamp for the customer managed key             |

## Section 3. Initial Bootstrap Operations

### Step A. Authenticate with Azure

The operator exports the target subscription and resource identifiers before logging in interactively to establish authenticated sessions for Azure and Microsoft Entra ID.

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

The operator exports the HTTP state backend credentials through the `administrator` Vault Proxy, which `terraform/.envrc` also loads.

```bash
eval "$(vault-proxy-env administrator)"
```

### Step C. Execute Terraform Layer Deployment

Initial layer deployment requires copying the variable template and configuring environment parameters.

- The operator creates `terraform.tfvars` by copying `terraform.tfvars.example`.
- The operator retains `is_premium_tier = false` to deploy the Standard tier.
- The operator replaces the documentation placeholder IP address in `key_vault_ip_rules` with the workstation public IPv4 CIDR block.
- This IP rule update prevents firewall lockout during subsequent Terraform execution.
- The group GitLab CI runner shares this public egress IP address for pipeline executions.
- The operator initializes the Terraform workspace to download provider plugins.
- The operator reviews planned infrastructure changes by running a speculative plan.
- The operator applies the configuration to provision Azure resources.

```bash
cd terraform/layers/group-ai-provider-azure
terraform init
terraform plan
terraform apply
```

## Section 4. Verification Procedures

### Item A. Remote State Outputs Verification

The operator inspects published Terraform outputs to confirm successful state persistence and contract generation.

```bash
terraform output
```

The published state outputs provide the following integration contracts:

- `tenant.id`: The Microsoft Entra ID tenant identifier discovered by `azuread_client_config`.
- `subscription.id`: The Azure subscription identifier discovered by `azurerm_client_config`.
- `resource_group.name`: The Azure Resource Group name housing cognitive services.
- `openai.id`: The Azure resource identifier of the Cognitive Services account.
- `openai.name`: The account name of the Azure OpenAI Cognitive Services instance.
- `openai.endpoint`: The HTTPS endpoint URL for Azure OpenAI API calls.
- `deployments`: The catalog mapping deployed model deployment identifiers and names.
- `network.private_endpoint_id`: The resource identifier of the cognitive account private endpoint, which evaluates to null on the Standard tier.
- `encryption.key_vault_id`: The resource identifier of the supporting Azure Key Vault instance.
- `encryption.key_id`: The versionless resource identifier of the customer managed encryption key.

### Item B. External Console and CLI Validation

The operator validates cognitive account provisioning directly against the Azure resource management API using the Azure CLI.

```bash
az cognitiveservices account show \
    --name "${AZURE_COGNITIVE_ACCOUNT_NAME}" \
    --resource-group "${AZURE_RESOURCE_GROUP_NAME}" \
    --output table
```

### Item C. Downstream Consumption Verification

The operator validates remote state accessibility by executing a test plan within a downstream consuming layer.

```bash
cd ../administration-gitlab-project
terraform init
terraform plan
```

- The plan execution reads the published remote state from `data.terraform_remote_state.group_ai_provider_azure`.
- The plan execution resolves `tenant.id`, `subscription.id`, and `openai.endpoint` attributes without remote state acquisition failures.

## Section 5. Credential Lifecycle and Maintenance

### Item A. Destruction Protection and Decommissioning

Lifecycle guardrails protect root cognitive infrastructure against accidental destruction and service disruption.

- The resources `azurerm_resource_group.openai` and `azurerm_cognitive_account.openai` declare `lifecycle { prevent_destroy = true }` protection blocks.
- This lifecycle rule prevents accidental destruction from breaking downstream Workload Identity Federation bindings and deleting model deployments.
- The resources `azurerm_key_vault.openai` and `azurerm_cognitive_account_customer_managed_key.openai` declare `lifecycle { prevent_destroy = true }` protection blocks.
- This encryption guardrail prevents cryptographic data loss by preserving the active encryption key material.
- Decommissioning the Key Vault requires an intentional administrative sequence.
- Purge protection cannot be disabled once enabled, hence a deleted Key Vault stays soft deleted for the 90 days of `soft_delete_retention_days` before Azure deletes the Key Vault permanently.
