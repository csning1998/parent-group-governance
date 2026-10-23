# Workstation Topology Specification and Engineering Reference

This specification defines the declarative configuration model for `workstation-topology.yaml`, detailing the human comprehension model, field-level schema definitions, and consuming codebase references across Ansible, Terraform, and Go CLI implementations.

## Section 1. Context and Constraints

1. The developer workstation hosts the root Bastion Vault instance, local operator forwarding proxies, and automated credential rotation routines for the homelab.
2. The current constraint is that multiple distinct tooling frameworks (Ansible automation, Terraform infrastructure layers, and Go governance CLI) depend on this configuration file without a unified single-source document explaining human operational semantics alongside engineering references.
3. The chosen path is to maintain `workstation-topology.yaml` as the authoritative declarative configuration with minimal inline commentary, accompanied by this specification serving as the complete API and literate reference.
4. The associated cost is that configuration schema mutations in `workstation-topology.yaml` require synchronized updates across this specification and all consuming codebase locations identified in Section 5.

## Section 2. Architectural Model

The topology file is organized into three distinct planes:

1. **Infrastructure Plane (`bastion_vault`)**: Configures daemon-level network listener interfaces and port bindings for the local Bastion Vault service.
2. **Access Plane (`operator_vault_proxy`)**: Configures local forwarding proxies mediating operator connections via mTLS client certificates, abstracting Vault token lifecycle management away from human operators and automation callers.
3. **Credential Lifecycle Plane (`service_admin_passwords`)**: Declares the registry of infrastructure service administrative accounts whose passwords undergo automated rotation by the Go governance CLI.

## Section 3. Schema and Field Reference

### Item A. Infrastructure Plane: `bastion_vault`

The `bastion_vault` map configures the network listener endpoints bound by the local Bastion Vault instance.

#### `bastion_vault.loopback_address`

- Type: `string` (IPv4 address literal)
- Default: `"127.0.0.1"`
- Constraint: The address MUST be an IPv4 loopback address bound exclusively to host-local loopback interfaces.
- Semantics: Dedicated interface for local operator CLI interactions and local Vault Proxy egress traffic. Host firewall rules MUST NOT expose this address to external or virtual networks.

#### `bastion_vault.publish_address`

- Type: `string` (IPv4 address literal)
- Default: `"172.16.0.1"`
- Constraint: The address MUST match the host gateway IP address assigned to the libvirt isolated bridge network (`workstation-isolated`).
- Semantics: Dedicated interface for guest virtual machines provisioned on the isolated bridge network to communicate with Bastion Vault APIs.

#### `bastion_vault.api_port`

- Type: `integer` (TCP port number)
- Default: `8200`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: Primary HTTPS listener port serving Vault client API requests.

#### `bastion_vault.cluster_port`

- Type: `integer` (TCP port number)
- Default: `8201`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: TCP port dedicated to Raft storage backend server-to-server cluster synchronization and request forwarding.

#### `bastion_vault.metrics_port`

- Type: `integer` (TCP port number)
- Default: `8202`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: TCP port exposing Prometheus telemetry metrics without authentication.

### Item B. Access Plane: `operator_vault_proxy`

The `operator_vault_proxy` map configures workstation-local forwarding proxies that authenticate callers via mTLS client certificates and inject valid Vault tokens.

#### `operator_vault_proxy.cert_auth_mount`

- Type: `string` (Vault auth mount path)
- Default: `"operator-cert"`
- Constraint: The mount path MUST match the certificate authentication backend path enabled on Bastion Vault.
- Semantics: Designates the cert auth mount path where operator client certificates authenticate against role names prefixed with `operator-`.

#### `operator_vault_proxy.user_config_dir`

- Type: `string` (Relative filesystem path)
- Default: `".config/vault-proxy"`
- Constraint: The path MUST be relative to the user home directory (`$HOME`).
- Semantics: Working directory where client TLS private keys, certificates, proxy configuration files (`proxy.hcl`), and systemd user unit definitions reside.

#### `operator_vault_proxy.placeholder_token`

- Type: `string` (Token literal)
- Default: `"proxy-supplied"`
- Constraint: The string MUST be non-empty and conform to ASCII token format.
- Semantics: Static placeholder token sent by client HTTP requests in the `X-Vault-Token` header. The local proxy interceptor strips this placeholder and substitutes a valid client token authenticated via mTLS.

#### `operator_vault_proxy.state_backend`

- Type: `object`
- Semantics: Declarative specification of the GitLab access token stored in Bastion Vault, utilized by Terraform HTTP remote state backends.
- Child fields:
    - `vault_kv_mount` (`string`): KV v2 secrets engine mount path (`secret`).
    - `vault_kv_path` (`string`): Full secret path holding the state backend token (`parent-group-governance/terraform/state-backend`).
    - `vault_kv_field` (`string`): JSON field name containing the token string (`token`).
    - `terraform_http_username` (`string`): Basic auth HTTP username required by GitLab HTTP remote state API (`gitlab-ci-token`).

#### `operator_vault_proxy.identities`

- Type: `map[string]IdentitySpec`
- Constraint: Sibling identity keys MUST use role or agent nouns. Sibling keys MUST NOT mix distinct naming dimensions. A tenant proxy key MUST equal the owner code of the tenant, since `outputs.tf` matches identity keys against the tenant registry of `access-tenant.tf`.
- Semantics: Registry of distinct operational identities running as local proxy systemd services. Callers bind their environment using `vault-proxy-env <identity>`.

### Item C. Credential Lifecycle Plane: `service_admin_passwords`

The `service_admin_passwords` list registers infrastructure services whose initial administrative credentials undergo automated rotation via the Go governance CLI.

#### Schema per list entry

- `key` (`string`): Unique identifier of the credential entry in CLI operations (e.g. `sonarqube-admin-password`).
- `vault_kv_mount` (`string`): KV v2 secrets engine mount path in Bastion Vault where the rotated password is saved (`secret`).
- `vault_kv_path` (`string`): Full KV secret path where the rotated password payload is saved (`parent-group-governance/sonarqube/admin-account`).
- `length` (`integer`): Character length of the generated random password (e.g. `24`).
- `service` (`object`): Service endpoint specification for executing credential lifecycle mutations:
    - `mechanism` (`string`): Protocol mechanism supported by target service (e.g. `http_form`).
    - `rotate_endpoint` (`string`): Target HTTP URL receiving password modification requests.
    - `verify_endpoint` (`string`): Target HTTP URL validating credential correctness via read-only authentication.
    - `admin_username` (`string`): Administrative account login username on the target service (`admin`).
    - `factory_default_password` (`string`): Out-of-the-box factory password required during initial bootstrap rotation.

## Section 4. Operator Identity Contract

The four operator identities defined in `operator_vault_proxy.identities` fulfill distinct security boundaries:

| Identity               | Access Tier            | Listen Port | Primary Scope   |
| ---------------------- | ---------------------- | ----------- | --------------- |
| credential-distributor | credential-distributor | 8210        | Read-only CI/CD |
| platform-foundation    | tenant                 | 8211        | Tenant Scope    |
| administrator          | administrator          | 8212        | Bastion Admin   |
| credential-rotator     | credential-rotator     | 8213        | Password Rotate |

1. `credential-distributor`:
    - Role: Distributes CI/CD credentials, runner tokens, and publication keys to repository setup scripts.
    - Rights: Read access to the state backend token and the secret paths declared under `allowed_read_secret_paths`. Write access is limited to the prefixes declared under `allowed_write_secret_paths`.
2. `platform-foundation`:
    - Role: Represents the `platform-foundation` repository tenant operator.
    - Rights: Receives the tenant policy of `access-tenant-acl.tf`, which covers `secret/platform-foundation/*`, the constrained PKI roles prefixed `platform-foundation-`, and the registry reader policy of the tenant.
3. `administrator`:
    - Role: Manages Bastion Vault root objects, policies, auth backends, and foundation-level secret objects.
    - Rights: Full administrative capabilities over `secret/parent-group-governance/*`, auth methods, audit devices, and policies.
4. `credential-rotator`:
    - Role: Executes automated password rotation for registered infrastructure services via `./governance credentials rotate`.
    - Rights: Scoped read and write permissions restricted exclusively to secret paths declared in `service_admin_passwords`.

## Section 5. Consuming Codebase Reference

### Item A. Infrastructure Plane Consumers

| Field              | Consuming Component                | Source File Path                                                     | Usage Description                                  |
| ------------------ | ---------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------- |
| `loopback_address` | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Populates `cluster_addr` and loopback listener.    |
| `publish_address`  | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Populates `api_addr` and isolated bridge listener. |
| `publish_address`  | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/libvirt-to-host.xml.j2` | Renders firewalld zone rich rule for VM bridge.    |
| `api_port`         | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures TCP port on HTTPS listeners.            |
| `api_port`         | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/context.tf`               | Assembles `local.bastion_vault_endpoint`.          |
| `api_port`         | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                     | Resolves `BastionVault.Endpoint` string.           |
| `cluster_port`     | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures Raft cluster synchronization TCP port.  |
| `metrics_port`     | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures unauthenticated telemetry TCP port.     |

### Item B. Access Plane Consumers

| Field               | Consuming Component                | Source File Path                                                        | Usage Description                                       |
| ------------------- | ---------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------- |
| `cert_auth_mount`   | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/access-operator-proxy.tf`    | Declares `vault_auth_backend.operator_cert` mount path. |
| `cert_auth_mount`   | Ansible workstation_vault_proxy    | `ansible/roles/workstation_vault_proxy/templates/proxy.hcl.j2`          | Configures cert auth mount in proxy HCL.                |
| `user_config_dir`   | Ansible workstation_vault_proxy    | `ansible/roles/workstation_vault_proxy/tasks/*.yaml`                    | Filesystem target for proxy units and certificates.     |
| `user_config_dir`   | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                        | Resolves certificate and socket filesystem paths.       |
| `placeholder_token` | Ansible workstation_vault_proxy    | `ansible/roles/workstation_vault_proxy/templates/vault-proxy-env.sh.j2` | Injects default `VAULT_TOKEN` environment variable.     |
| `placeholder_token` | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                        | Sets `ProxyEndpoint.Token` value.                       |
| `state_backend`     | Ansible workstation_vault_proxy    | `ansible/roles/workstation_vault_proxy/templates/vault-proxy-env.sh.j2` | Queries Bastion Vault to export `TF_HTTP_*` variables.  |
| `identities`        | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/access-operator-proxy.tf`    | Declares policies and roles per identity.               |
| `identities`        | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/outputs.tf`                  | Exports `bastion_vault_tenant.operator_role`.           |
| `identities`        | Ansible workstation_vault_proxy    | `ansible/roles/workstation_vault_proxy/tasks/D-service.yaml`            | Deploys systemd unit `vault-proxy@<identity>.service`.  |
| `identities`        | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                        | Resolves proxy port and checks identity tiers.          |
| `identities`        | Go CLI operations                  | `tools/governance/cmd/governance/operations.go`                         | References proxy identities for operational flows.      |
| `identities`        | All homelab repositories           | `.envrc` files                                                          | Consumes `vault-proxy-env <identity>` commands.         |

### Item C. Credential Lifecycle Plane Consumers

| Field                     | Consuming Component                | Source File Path                                                     | Usage Description                                               |
| ------------------------- | ---------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------- |
| `service_admin_passwords` | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/access-operator-proxy.tf` | Generates paths for `vault_policy.operator_credential_rotator`. |
| `service_admin_passwords` | Go CLI credentials package         | `tools/governance/pkg/credentials/credentials.go`                    | Implements Vault KV retrieval and persistence.                  |
| `service_admin_passwords` | Go CLI httprotate package          | `tools/governance/pkg/httprotate/httprotate.go`                      | Executes HTTP form-based authentication and rotation.           |
| `service_admin_passwords` | Go CLI operations                  | `tools/governance/cmd/governance/operations.go`                      | Drives the password rotation loop in `runCredentialsRotate`.    |
| `service_admin_passwords` | Go CLI menu                        | `tools/governance/cmd/governance/menu.go`                            | Exposes TUI menu items for credential rotation.                 |

---
