# Workstation Topology Specification and Engineering Reference

This specification defines the declarative configuration model for `workstation-topology.yaml`, detailing the human comprehension model, field-level schema definitions, and consuming codebase references across Ansible, Terraform, and Go CLI implementations.

## Section 1. Context and Constraints

1. The developer workstation hosts the root Bastion Vault instance, local operator forwarding proxies, and automated credential rotation routines for the homelab.
2. The current constraint is that multiple distinct tooling frameworks (Ansible automation, Terraform infrastructure layers, and Go governance CLI) depend on this configuration file without a unified single-source document explaining human operational semantics alongside engineering references.
3. The chosen path is to maintain `workstation-topology.yaml` as the authoritative declarative configuration with minimal inline commentary, accompanied by this specification serving as the complete API and literate reference.
4. The associated cost is that configuration schema mutations in `workstation-topology.yaml` require synchronized updates across this specification and all consuming codebase locations identified in Section 5.

## Section 2. Architectural Model

The topology file is organized into five distinct planes:

1. **Infrastructure Plane (`vault_bastion`)**: Configures daemon-level network listener interfaces and port bindings for the local Bastion Vault service.
2. **Observability Plane (`host_telemetry_scrape`)**: Declares the registry location of the host telemetry scrape segment and the exporter ports of the host, which `./governance host apply-host-telemetry` opens to the observability scrapers.
3. **Access Plane (`operator_vault_proxy`)**: Configures local forwarding proxies mediating operator connections via mTLS client certificates, abstracting Vault token lifecycle management away from human operators and automation callers.
4. **Credential Lifecycle Plane (`service_admin_passwords`)**: Declares the registry of infrastructure service administrative accounts whose passwords undergo automated rotation by the Go governance CLI.
5. **Credential Issuance Plane (`service_issued_tokens`)**: Declares the tokens which SonarQube and GitLab issue and `./governance credentials issue` writes into the Bastion Vault, GitLab CI/CD variables, and the runner configuration.

## Section 3. Schema and Field Reference

### Item A. Infrastructure Plane: `vault_bastion`

The `vault_bastion` map configures the network listener endpoints bound by the local Bastion Vault instance.

#### `vault_bastion.loopback_address`

- Type: `string` (IPv4 address literal)
- Default: `"127.0.0.1"`
- Constraint: The address MUST be an IPv4 loopback address bound exclusively to host-local loopback interfaces.
- Semantics: Dedicated interface for local operator CLI interactions and local Vault Proxy egress traffic. Host firewall rules MUST NOT expose this address to external or virtual networks.

#### `vault_bastion.publish_address`

- Type: `string` (IPv4 address literal)
- Default: `"172.16.0.1"`
- Constraint: The address MUST match the host gateway IP address assigned to the libvirt isolated bridge network (`workstation-isolated`).
- Semantics: Dedicated interface for guest virtual machines provisioned on the isolated bridge network to communicate with Bastion Vault APIs. The TLS terminator `vault-terminator` binds the address, and no Vault listener binds the address.

#### `vault_bastion.api_port`

- Type: `integer` (TCP port number)
- Default: `8200`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: Primary HTTPS listener port serving Vault client API requests.

#### `vault_bastion.cluster_port`

- Type: `integer` (TCP port number)
- Default: `8201`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: TCP port dedicated to Raft storage backend server-to-server cluster synchronization and request forwarding.

#### `vault_bastion.metrics_port`

- Type: `integer` (TCP port number)
- Default: `8202`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535).
- Semantics: TCP port exposing Prometheus telemetry metrics without authentication. Vault binds the port on the loopback address, and the TLS terminator binds the port on the publish address and admits `GET /v1/sys/metrics` alone.

#### `vault_bastion.publish_backend_port`

- Type: `integer` (TCP port number)
- Default: `8204`
- Constraint: The port MUST be a valid, unprivileged TCP port (1024-65535). The port MUST differ from `metrics_port` plus one, since Vault opens a cluster listener one port above every API listener.
- Semantics: Loopback TCP port of the Vault listener which accepts PROXY protocol v2 from the TLS terminator.

#### `host_telemetry_scrape` (Observability Plane)

- Type: `object`
- Semantics: The host segment on which the observability scrapers reach the metrics of the host, the third octet 249 of the network allocation (ADR-143). The network allocation facts reside in the Bastion Vault, hence the file declares the registry location of the segment instead of the segment.
- Child fields:
    - `network_name` (`string`): Name of the routed libvirt network which carries the host address on the segment (`host-telemetry-scrape`).
    - `registry` (`object`): `vault_kv_mount`, `vault_kv_path`, `cidr_field`, and `address_field` of the segment and the host address, which `foundation-vault-bastion` publishes at `registry/platform/network/allocation`.
    - `host_exporter_ports` (`list(number)`): Ports of node_exporter and the libvirt exporter on the host. The scrape ports are these ports and `vault_bastion.metrics_port`.

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
    - `vault_kv_field` (`string`): JSON field name containing the token string (`token`).
    - `terraform_http_username` (`string`): Basic auth HTTP username required by GitLab HTTP remote state API (`gitlab-ci-token`).
    - `project_ids` (`map(string)`): ID of the GitLab project storing the state files of each owner code, such as `parent-group-governance: "86417732"`. `vault-proxy-env` exports `GITLAB_TERRAFORM_STATE_BASE` for every identity whose owner the map lists. The GitLab API URL derives from the origin remote of this repository, which the CLI injects into the role `workstation_vault_proxy`.

#### `operator_vault_proxy.governance_owner_code`

- Type: `string`
- Semantics: Owner code of this repository (`parent-group-governance`). The identities `administrator` and `credential-rotator` carry the owner code, and the administrator writes below `secret/<governance_owner_code>/`. The field is the single declaration of the governance owner code for Terraform, Ansible, and the CLI.

#### `operator_vault_proxy.identities`

- Type: `map[string]IdentitySpec`
- Constraint: Sibling identity keys MUST name operator Proxy identities. Sibling keys MAY span naming dimensions, since the owner code exclusion of Item F and the reserved words of Item G in Section 3 of the organization naming standard prevent a collision. A tenant proxy key MUST equal the owner code of the tenant, since `outputs.tf` matches identity keys against the tenant registry of `access-tenant.tf`.
- Semantics: Registry of distinct operational identities running as local proxy systemd services. Callers bind their environment using `vault-proxy-env <identity>`.
- Fields of `IdentitySpec`:
    - `listen_port` (`number`): Loopback port of the Proxy, distinct across identities.
    - `allowed_read_secret_paths` and `allowed_write_secret_paths` (`list(string)`): KV paths of whole segments, declared by `credential-distributor` alone. Identical lists SHOULD share one YAML anchor.
    - `allowed_read_registry_paths` (`list(string)`): Registry domains below `platform/`, such as `platform/ai-provider`, declared by `credential-distributor` and `consumer`.
    - `code_reviewer_variable_projects` (`list(string)`): Project paths below the top-level group, such as `platform-engineering-lab/platform-foundation`, which receive the code reviewer bot variables from `./governance credentials issue code-reviewer-variables`. The CLI prefixes the top-level group of the origin remote. Only `workstation-topology.yaml` grants a project the bot tokens, and a project cannot register itself.
- Naming: The identity key determines the access tier and the owner code, and the file declares neither field.
    - `administrator` and `credential-rotator` carry the tier of the same name and `governance_owner_code`.
    - `credential-distributor-<owner code>` and `consumer-<owner code>` carry the tier of the prefix and the owner code after the prefix.
    - Every other key is a tenant, and the key equals the owner code of the tenant.
    - Every identity except `credential-rotator` reads the GitLab token of its owner at `<owner code>/terraform/state-backend`, and `vault-proxy-env` exports the token as `TF_HTTP_PASSWORD`.
    - The Go package `internal/topology`, the locals of `access-operator-proxy.tf`, and the template `vault-proxy-env.sh.j2` implement the same rule.

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

### Item D. Credential Issuance Plane: `service_issued_tokens`

The `service_issued_tokens` object declares the tokens which a service issues. A Terraform-managed write would store each token in the state, hence `./governance credentials issue` writes each token through the administrator Vault Proxy.

The CLI derives the GitLab REST API URL and the runner URL from the origin remote of this repository, and reads the GitLab token of `credential-distributor-<governance_owner_code>` for every API call.

- `gitlab_group_registry` (`object`): `vault_kv_mount`, `vault_kv_path`, and `vault_kv_field` of the top-level group ID in the registry.
- `sonarqube_analysis_token` (`object`):
    - `user_tokens_endpoint` (`string`): The `api/user_tokens` web service of SonarQube.
    - `admin_password_key` (`string`): The `key` of the `service_admin_passwords` entry whose account issues the token.
    - `token_name_prefix` (`string`): Name prefix of every issued token. A rotation revokes the bare prefix and every earlier name of the prefix and a hyphen.
    - `vault` (`object`): `vault_kv_mount`, `vault_kv_path`, and `vault_kv_field` of the token in the Bastion Vault.
    - `gitlab_group_variable_key` (`string`): Group CI/CD variable receiving the token (`SONAR_TOKEN`).
- `gitlab_group_runner` (`object`):
    - `description` (`string`): Runner description in the group settings and runner name in `config.toml`.
    - `tag_list` (`list(string)`): Job tags which the runner accepts.
    - `config_path` (`string`): Path of `config.toml` relative to the project root. An existing file refuses the registration.
- `code_reviewer_variables` (`object`):
    - `bot_tokens` (`list(object)`): Each entry maps one Bastion Vault field (`vault`) to the project variable keys (`variable_keys`) receiving the token. `foundation-vault-bastion` grants the administrator identity read access on each listed path.

## Section 4. Operator Identity Contract

The four operator identities defined in `operator_vault_proxy.identities` fulfill distinct security boundaries:

| Identity                                       | Access Tier            | Listen Port | Primary Scope   |
| ---------------------------------------------- | ---------------------- | ----------- | --------------- |
| credential-distributor-parent-group-governance | credential-distributor | 8210        | Read-only CI/CD |
| platform-foundation                            | tenant                 | 8211        | Tenant Scope    |
| administrator                                  | administrator          | 8212        | Bastion Admin   |
| credential-rotator                             | credential-rotator     | 8213        | Password Rotate |

1. `credential-distributor-parent-group-governance`:
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

| Field                  | Consuming Component                | Source File Path                                                     | Usage Description                                 |
| ---------------------- | ---------------------------------- | -------------------------------------------------------------------- | ------------------------------------------------- |
| `loopback_address`     | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Populates `cluster_addr` and loopback listener.   |
| `publish_address`      | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Populates `api_addr`.                             |
| `publish_address`      | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/libvirt-to-host.xml.j2` | Renders firewalld zone rich rule for VM bridge.   |
| `api_port`             | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures TCP port on HTTPS listeners.           |
| `api_port`             | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/context.tf`               | Assembles `local.vault_bastion_endpoint`.         |
| `api_port`             | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                     | Resolves `BastionVault.Endpoint` string.          |
| `cluster_port`         | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures Raft cluster synchronization TCP port. |
| `metrics_port`         | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures unauthenticated telemetry TCP port.    |
| `publish_address`      | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/haproxy.cfg.j2`         | Binds the terminator frontends.                   |
| `publish_address`      | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/tasks/E-vault-config.yaml`        | Renders `TERMINATOR_PUBLISH_ADDRESS`.             |
| `loopback_address`     | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/tasks/E-vault-config.yaml`        | Renders `VAULT_ADDR` of `vault-server`.           |
| `publish_backend_port` | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/vault.hcl.j2`           | Configures the PROXY protocol listener.           |
| `publish_backend_port` | Ansible workstation_libvirt        | `ansible/roles/workstation_libvirt/templates/haproxy.cfg.j2`         | Targets the terminator API backend.               |

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
| `identities`        | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/outputs.tf`                  | Exports `vault_bastion_tenant.operator_role`.           |
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

### Item D. Credential Issuance Plane Consumers

| Field                                          | Consuming Component                | Source File Path                                                     | Usage Description                                                     |
| ---------------------------------------------- | ---------------------------------- | -------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `service_issued_tokens`                        | Go CLI issuedtokens package        | `tools/governance/pkg/issuedtokens/config.go`                        | Parses the token declarations.                                        |
| `service_issued_tokens`                        | Go CLI issued token operations     | `tools/governance/cmd/governance/issued_tokens.go`                   | Drives the three `credentials issue` subcommands.                     |
| `code_reviewer_variables.bot_tokens`           | Terraform foundation-vault-bastion | `terraform/layers/foundation-vault-bastion/access-operator-proxy.tf` | Grants the administrator identity read access on each bot token path. |
| `identities.*.code_reviewer_variable_projects` | Go CLI topology package            | `tools/governance/internal/topology/topology.go`                     | Lists the projects receiving the code reviewer variables.             |
| `host_telemetry_scrape.registry`               | Go CLI operations                  | `tools/governance/cmd/governance/operations.go`                      | Reads the segment which `apply-host-telemetry` injects.               |
| `host_telemetry_scrape`                        | Ansible workstation_host_telemetry | `ansible/roles/workstation_host_telemetry/tasks/main.yaml`           | Declares the network and the firewalld policy of the segment.         |

---
