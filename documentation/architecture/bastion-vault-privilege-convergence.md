# Bastion Vault Privilege Convergence Architecture

This document records the privilege boundaries, roots of trust, fact publications, audits, and the supporting `./governance` CLI on the Bastion Vault for `parent-group-governance` (referred to below as pgg). The intended audience includes engineers maintaining pgg and `platform-foundation` (referred to below as mp). Concrete names and addresses in this document are the example values of `platform-trust.example.json`, with `10.20.0.1` as the Bastion publish address.

## Section 1. Scope and Terminology

### Item A. Scope

1. This document covers the pgg layer `foundation-vault-bastion`.
2. This document covers packages and commands related to Bastion Vault privileges in `tools/governance`.
3. This document covers the Ansible roles `workstation_vault_audit` and `workstation_vault_proxy`.
4. How the mp side consumes the registry and the operator Vault Proxy is documented in `architecture_platform-foundation_deployment-chain.md` within the planning repository. This document describes only the interface provided by pgg.

### Item B. Terminology Definitions

- **Bastion Vault**: The `hashicorp/vault:2.0` OSS instance running via podman compose on the operator workstation, listening on `127.0.0.1:8200` and `10.20.0.1:8200`.
- **Tenant**: A product repository granted a restricted set of privileges on the Bastion Vault and identified by an owner code, such as `platform-foundation`.
- **Owner Code**: An identifier string for a tenant, formatted as lowercase alphanumerics connected by hyphens, such as `platform-foundation`, denoted as `<code>` below.
- **root token**: The Bastion Vault root token, which `~/.vault-token` holds during the bootstrap and a break-glass alone.
- **Operator identity**: An entry of `operator_proxy.identities` in `workstation-topology.yaml`, such as `governance`, `platform-foundation`, `parent-group-governance`, or `service-admin-passwords`, with access `governance`, `tenant`, `foundation`, or `rotation`.
- **Operator Vault Proxy**: The Vault Proxy of one operator identity on the operator workstation, which logs in through the cert auth mount `operator-cert` and overwrites the token of every request on its loopback mTLS listener.
- **Operator cert role**: The cert auth role `operator-<identity>`, which admits the client certificate of CN `operator-<identity>` signed by the local CA of `vault/tls`.
- **Assignment Scope**: The set of policy names which a tenant role on one class of auth mount is allowed to carry.
- **registry**: The KV v2 mount `registry`, in which pgg publishes the facts needed by tenants and which only pgg writes.
- **Name Constraints**: The certificate extension defined by RFC 5280 which restricts the names which certificates issued under a given CA certificate may carry.

## Section 2. Background, Threats, and Design Principles

### Item A. Protected Assets

1. The issuance capabilities of `pki-root` and subordinate intermediate CAs. The trust bundles of both the workstation and platform nodes trust `pki-root`. An issuer able to produce a certificate chaining back to `pki-root` can impersonate any service which those trust bundles accept.
2. The unseal capability of the Downstream Vault. Decrypt privileges on the transit key, combined with the encrypted root key in the Downstream Vault storage, yield the root key of the Downstream Vault, which is equivalent to acquiring all secrets inside the Downstream Vault.
3. The authorization boundaries between tenants, as well as between tenants and pgg.
4. Platform trust facts, specifically domains, SPIRE trust domains, and CIDR blocks. These values determine the permitted and excluded scopes of Name Constraints.
5. Audit logs. The audit log serves as the sole ground truth for forensic analysis.

### Item B. Threat Sources

1. Leaked tenant tokens or secret IDs, such as values lingering in terminal scrollback, process environments, or Terraform state files.
2. Compromised mp layers, mp component operators, or CI jobs.
3. Compromised private keys of the SPIRE CA or the Downstream Vault CA.
4. Individuals or processes with read access to the Terraform state of the pgg project.
5. Processes executing under the operator workstation account which were not initiated by the operator directly.
6. Operator errors, such as relaxing constraints in local tfvars or executing commands in the wrong shell context.

### Item C. Threat Scenarios and Consequences

Each row in the table below represents a threat scenario. The unmitigated consequence column details what an attacker can achieve in the absence of controls, and the countermeasure column points to the corresponding section of this document.

| ID  | Scenario                                                                 | Unmitigated Consequence                                                                                                                                                                                                                                                                                                                                 | Countermeasure                       |
| --- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| T1  | A tenant has write access to both policies and auth roles simultaneously | The tenant writes a policy containing `path "*"` and assigns the policy to a role of the tenant, obtaining full Bastion Vault privileges, including intermediate CA issuance and transit key decryption                                                                                                                                                 | Section 3 Item E                     |
| T2  | `allowed_parameters` matches policy names via glob patterns              | Strings like `<code>-a,other` are split into two distinct policies by the auth method, allowing the tenant to assign policies outside its assignment scope                                                                                                                                                                                              | Section 3 Item E.1                   |
| T3  | Operator login credentials are issued by Terraform                       | Secret IDs or tokens enter state files, outputs, and KV storage, allowing any layer with read access to pgg state to log in as the operator identity indefinitely                                                                                                                                                                                       | Section 3 Item D                     |
| T4  | mp reads pgg state via `terraform_remote_state`                          | The reader acquires the entire state snapshot. If the GitLab token used for reading carries the Maintainer role, the reader could tamper with pgg state to induce unintended actions during the next apply                                                                                                                                              | Section 4 Item C                     |
| T5  | Published facts reside on paths writable by the tenant                   | The tenant tampers with the domains or CIDR blocks constraining itself, causing subsequent layers reading those facts to apply relaxed values                                                                                                                                                                                                           | Section 4 Item C.2                   |
| T6  | Platform trust facts can be overridden by tfvars, `-var`, or `TF_VAR_`   | An uncommitted local value can relax Name Constraints without visibility in the code review process                                                                                                                                                                                                                                                     | Section 4 Item A                     |
| T7  | Intermediate CAs lack Name Constraints                                   | A compromised SPIRE or Downstream Vault CA can issue certificates for `127.0.0.1` or `10.20.0.1` to spoof the Bastion Vault listener. An attacker who also controls the network path, such as DNS or routing, receives the tokens of clients which trust the `pki-root` bundle. Clients pinned to `MetaProvisionVaultCA` reject the spoofed certificate | Section 4 Item B                     |
| T8  | Downstream Vault CA is allowed to issue SPIFFE URIs                      | A compromised Downstream Vault can issue arbitrary SVIDs to impersonate any workload identity                                                                                                                                                                                                                                                           | Section 4 Item B.2                   |
| T9  | The transit unseal policy is assignable on shared mounts                 | A leaked tenant token creates a GitLab CI JWT role with overly broad claims and attaches the transit unseal policy, allowing any CI job with network reachability to the Bastion Vault to decrypt the Downstream Vault root key once the CI job also obtains the encrypted root key from the Downstream Vault storage                                   | Section 3 Item E.3                   |
| T10 | The transit key is exportable or allows plaintext backup                 | An attacker obtaining the key and the encrypted root key from the Downstream Vault storage can decrypt the root key offline without leaving any decrypt entries in audit logs                                                                                                                                                                           | Section 4 Item D                     |
| T11 | The terminal outputs token accessors                                     | An accessor captured in scrollback can be used by an identity holding `lookup-accessor` or `revoke-accessor` privileges to inspect or revoke operator tokens                                                                                                                                                                                            | Section 5 Item C                     |
| T12 | Audit devices are disabled or modified without detection                 | Operations executed by an attacker after disabling audit logging leave no traces, making post-incident investigation impossible                                                                                                                                                                                                                         | Section 5                            |
| T13 | An operator login credential is intercepted in transit                   | The interceptor replays the credential and logs in as the operator identity, and the legitimate workflow does not notice the second login                                                                                                                                                                                                               | Section 3 Item D.3                   |
| T14 | The root token or ambient `VAULT_TOKEN` is sent with requests            | The root token reaches a Proxy or an operator shell, effectively elevating the operator identity to root                                                                                                                                                                                                                                                | Section 3 Item D.3, Section 6 Item C |
| T15 | Operator tokens reside in shell environments                             | Every process of the shell inherits the token, and a token printed or captured from the environment stays valid within its TTL for other processes on the same host                                                                                                                                                                                     | Section 3 Item D.3                   |
| T16 | A tenant manages leaf roles on an issuing mount without Name Constraints | The tenant creates a role without name restrictions on `pki-intermediate` and issues a certificate for `127.0.0.1` or `10.20.0.1` which chains to `pki-root`, without compromising any CA                                                                                                                                                               | Section 4 Item B.2                   |
| T17 | A CA signer policy is assignable on the GitLab CI JWT mount              | A CI job assigned `pki-spire-signer-<code>` signs a SPIRE CA under `pki-spire` and mints any SVID of the trust domain                                                                                                                                                                                                                                   | Section 3 Item E.3                   |

### Item D. Existing Constraints

1. Vault OSS does not provide Sentinel, namespaces, or audit filters.
2. Vault OSS does not enforce content restrictions on policies. Vault OSS also does not restrict which policies an auth role can assign.
3. An identity capable of writing both policies and auth roles can craft a policy containing `path "*"` and assign the policy to a role of the identity, obtaining arbitrary privileges.
4. When `allowed_parameters` in ACLs matches via glob patterns, strings containing commas such as `<code>-a,other` are accepted and subsequently split into two separate policies by the auth method.
5. `terraform_remote_state` downloads the complete state snapshot, giving readers access to all resource attributes. `sensitive = true` only masks values in CLI output.
6. Reading Terraform state from GitLab requires the Developer role, while writing and locking state requires the Maintainer role.
7. Destroying a `vault_kv_secret_v2` resource with the default `delete_all_versions = false` soft deletes only the latest version. Earlier versions stay readable, and the latest version stays recoverable until the versions are destroyed or the metadata is deleted.
8. Vault provider 5.5.0 deprecated the data source `vault_kv_secret_v2`.

### Item E. Design Principles

1. Every privilege MUST be held by the lowest identity in the hierarchy.
2. Every Vault path MUST have only one writer.
3. Every authorization boundary value MUST have a single declaration source, and that source MUST undergo version control and review.
4. Secrets MUST NOT enter any Terraform state, KV copy, or output.
5. Any check failure MUST abort the entire workflow. Partial results MUST NOT be applied.
6. Daily operations MUST NOT require manual credential delivery.

## Section 3. Identity and Permission Hierarchy

### Item A. Hierarchy Overview

Identities on the Bastion Vault are structured into five tiers. Each tier receives its policies from the tier above, and a tier cannot obtain a policy which the tier above has neither declared nor placed within an assignment scope.

| Tier | Identity                 | Acquisition Method                                      | Privilege Scope                                                      | Location                                     |
| ---- | ------------------------ | ------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------- |
| L0   | root token               | Vault initialization                                    | Complete privileges on Bastion Vault                                 | `~/.vault-token` on the operator workstation |
| L1   | pgg Terraform            | The foundation Proxy, root for the first apply alone    | Declaring mounts, policies, roles, PKI, and registry                 | The Terraform process of pgg                 |
| L2   | tenant operator token    | Logged in by the Proxy of a tenant identity, cert auth  | Tenant ACL and `registry-reader-<code>`                              | Memory of the Vault Proxy of the identity    |
| L2   | governance token         | Logged in by the governance Proxy, cert auth            | Reads on the group keys alone                                        | Memory of the governance Vault Proxy         |
| L3   | Component operator token | Logged in to the Downstream Vault with a SPIRE JWT-SVID | None on the Bastion Vault, and policies on the Downstream Vault      | The Terraform process of mp                  |
| L4   | Workload token           | Logged in via Kubernetes auth, AppRole, or JWT          | Single-purpose policies, such as transit unseal or sign-intermediate | Workload processes                           |

### Item B. L0 root token

1. The root token MUST only be used on the operator workstation.
2. The root token serves the bootstrap alone: `vault init`, `vault enable-kv`, the first writes of the state backend token and the platform trust facts, and the first apply of `foundation-vault-bastion` through `vault-proxy-env root`. `./governance vault revoke-root` then revokes the token, and `./governance vault generate-root` restores one from the unseal key quorum for a break-glass.
3. The root token MUST NOT reach a Vault Proxy or the environment of a non-root identity. `vault-proxy-env` unsets `VAULT_TOKEN` for the identity `root`, and prints the placeholder token for every other identity.
4. Every use of the root token triggers a `vault-audit-alert`, which serves as an expected operational signal.

### Item C. L1 pgg Terraform

1. The Terraform runs for pgg are executed on the operator workstation through the Vault Proxy of the identity `parent-group-governance`, access `foundation`, after the first apply of `foundation-vault-bastion` with the root token.
2. `foundation-vault-bastion` declares auth mounts, PKI mounts, transit mounts, registry mounts, audit devices, the operator cert auth mount and cert roles, and policies held by pgg.
3. `foundation-vault-bastion` also declares the tenant ACL and every policy which a tenant may assign.
4. The state file of the layer is stored in GitLab project `86417732`, and the state MUST NOT contain any secrets, as verified in Section 9 Step E.
5. Applies MUST use a saved plan: executing `terraform plan -out=tfplan` first, followed by `terraform apply tfplan` after review.

### Item D. L2 Operator Vault Proxy

This section addresses T3, T13, T14, and T15 from Section 2 Item C. Every non-root login to the Bastion Vault runs through the Vault Proxy of one operator identity. A caller holds no Vault token, hence a leaked shell environment or a leaked state file exposes no credential which logs in.

#### Item D.1 Declaration of the Operator Cert Roles

`foundation-vault-bastion/access-operator-proxy.tf` declares the cert auth mount `operator-cert` and one cert role per entry of `operator_proxy.identities` in `workstation-topology.yaml`.

| Attribute              | Value                                                                                                                                       | Rationale                                                                                                                       |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `name`                 | `operator-<identity>`                                                                                                                       | The role name matches the CN which the role admits.                                                                             |
| `certificate`          | The local CA `vault/tls/ca.pem`                                                                                                             | The CA of the Bastion listener signs the client certificates, hence the workstation holds one CA alone.                         |
| `allowed_common_names` | `operator-<identity>`                                                                                                                       | A certificate of one identity cannot log in through the role of another identity.                                               |
| `token_policies`       | `operator-<identity>` for access `governance`, `foundation`, or `rotation`; the tenant ACL and `registry-reader-<code>` for access `tenant` | A governance identity reads group keys alone. Foundation and rotation hold scoped administrative policies. Tenant holds Item E. |
| `token_ttl`            | 3600s                                                                                                                                       | The Proxy renews the token within the TTL.                                                                                      |
| `token_max_ttl`        | 14400s                                                                                                                                      | The Proxy logs in again after the maximum TTL.                                                                                  |
| `token_bound_cidrs`    | `127.0.0.1/32`                                                                                                                              | The Proxies connect through the loopback listener, and a token presented from any other source fails.                           |

`terraform_data.operator_identities_validation` stops the plan when an identity declares an access other than `governance`, `tenant`, `foundation`, or `rotation`, when there is not exactly one `governance` identity, exactly one `foundation` identity, and exactly one `rotation` identity, or when a tenant identity names no tenant of `access-tenant.tf`. Terraform MUST NOT declare any client certificate, private key, secret ID, or token.

#### Item D.2 Workflow of the Operator Vault Proxy

The role `workstation_vault_proxy` of the first menu item `[Host] Apply All Workstation Prerequisites` installs the Proxies.

1. The role generates an ECDSA P-256 client key of mode `0600` per identity, and the local CA signs a client certificate of CN `operator-<identity>` for 365 days. A second certificate of CN `vault-proxy-<identity>` serves the loopback listener of the Proxy.
2. The role reissues a certificate within 30 days of expiry, or when the certificate no longer verifies against the CA.
3. The systemd user unit `vault-proxy@<identity>.service` runs `vault proxy` with `auto_auth` method `cert`, `api_proxy` with `use_auto_auth_token = "force"`, and a TCP listener on `127.0.0.1` at the port of the identity.
4. The listener sets `tls_require_and_verify_client_cert` with the local CA, hence a process without the client key of the identity cannot reach the Proxy.
5. `vault-proxy-env <identity>` prints `VAULT_ADDR` of the Proxy, `VAULT_CACERT`, `VAULT_CLIENT_CERT`, `VAULT_CLIENT_KEY`, the placeholder `VAULT_TOKEN`, `TERRAFORM_VAULT_SKIP_CHILD_TOKEN=true`, and `TF_HTTP_USERNAME` with `TF_HTTP_PASSWORD`. A `.envrc` of each repository or layer loads the output through direnv.

#### Item D.3 Token Boundary Guarantees

1. The Bastion Vault token of an operator identity MUST reside in the memory of the Proxy alone. The Proxy overwrites the placeholder token of every request.
2. The Vault provider MUST skip the child token, since a child token from `auth/token/create` does not carry `token_bound_cidrs` and the cert role grants no `auth/token/create`.
3. The long lived credential is the client private key. The key never leaves the operator workstation and never enters a Terraform state, an output, or a KV path.
4. No secret ID and no wrapping token exist in the operator login, hence no credential crosses the network outside the mTLS handshake.
5. The identity `root` uses the token helper `~/.vault-token` and bypasses every Proxy, since root applies the cert roles which every Proxy needs.

#### Item D.4 Usage Conditions

1. The platform-foundation Proxy carries every mp layer and Ansible play which reads `registry` or changes a resource on the Bastion Vault.
2. The layers which require the Proxy are the foundation layer, the SPIRE Parent layers, and the Downstream Vault layers, as listed in `architecture_platform-foundation_deployment-chain.md` within the planning repository.
3. After the Downstream Vault is established, the remaining mp layers authenticate to the Downstream Vault with SPIRE JWT-SVIDs and do not operate on the Bastion Vault.
4. Rebooting the Bastion Vault requires only `./governance vault unseal`. The Proxies log in again without an operator action.

#### Item D.5 Governance Identity

The tenant registry lists platforms alone, and a repository of the group registers no tenant for the governance layer. Every governance layer of the group runs through the governance Proxy.

1. The policy `operator-governance` reads `parent-group-governance/terraform/state-backend` and the paths of `reads` of the identity in `workstation-topology.yaml`, and writes nothing.
2. The paths of `reads` are the group keys: the Anthropic admin key, the GitHub publication token, the SonarQube analysis token, and the two bot tokens below `gitlab-ci-with-code-reviewer/integration`.
3. The Workload Identity Federation module writes no Vault path, hence a governance layer holds no Vault write privilege.

#### Item D.6 Foundation Identity

The foundation identity replaces the root token after the bootstrap for everyday `parent-group-governance` post-bootstrap operations.

1. The policy `operator-parent-group-governance` manages every mount, auth method, audit device, and policy declared in `foundation-vault-bastion`.
2. The policy grants `manage_mount` and `administer` capabilities across `foundation_mount_paths` (`pki-root`, `pki-intermediate`, `transit-unseal`, `registry`, and constrained intermediate mounts).
3. The policy grants `manage_mount` and `administer` capabilities across `foundation_auth_paths` (`approle`, `operator-cert`, `gitlab-saas-ci-job-jwt-provider`).
4. The policy grants `manage_mount` across `foundation_audit_paths` (`file`, `stdout`) and permits Raft snapshot reads on `sys/storage/raft/snapshot`.
5. The policy grants CRUD on KV paths under `parent-group-governance/` on the state backend mount.

#### Item D.7 Rotation Identity

The rotation identity scopes privileges strictly to secret rotation routines executed by the governance CLI.

1. The policy `operator-service-admin-passwords` grants `kv_rotate` on `${password.vault_kv_mount}/data/${password.vault_kv_path}` for every entry of `service_admin_passwords` in `workstation-topology.yaml`.
2. The policy grants `read` on the corresponding metadata paths, and writes nothing outside the declared service admin passwords.

### Item E. L2 Tenant ACL

This section addresses T1, T2, T9, and T17 from Section 2 Item C. Vault OSS does not restrict the content of a policy. pgg therefore declares every policy on the Bastion Vault, and a tenant does not write or request any policy.

#### Item E.1 Declaration

1. `foundation-vault-bastion/access-tenant-acl.tf` declares the tenant ACL under the name `<code>-terraform-operator`.
2. The tenant ACL MUST NOT grant any write on `sys/policies/acl`.
3. Every rule which writes auth roles MUST restrict `token_policies` and `policies` through `allowed_parameters` to exact policy names.
4. A rule MUST NOT use a glob in `allowed_parameters`, because a glob admits a comma separated string which the auth method splits into two policies.
5. `terraform_data.tenant_owner_codes_validation` carries a precondition which stops the plan when an owner code followed by a hyphen prefixes another owner code.

#### Item E.2 Rule Categories

The tenant ACL comprises five categories of rules.

| Category     | Path                                                                                                                                       | Capabilities                                                                     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| kv           | `secret/data/<code>/*`, `secret/metadata/<code>/*`, `secret/delete/<code>/*`, `secret/destroy/<code>/*`, `sys/internal/ui/mounts/secret/*` | Data read and write, metadata management, version deletion and destruction       |
| auth mount   | `sys/auth`, `sys/auth/<code>-*`, `sys/mounts/auth/<code>-*`, `auth/<code>-*`                                                               | Creation and configuration of tenant owned auth mounts                           |
| auth role    | `auth/approle/role/<code>-*`, `auth/gitlab-saas-ci-job-jwt-provider/role/<code>-*`                                                         | Management of tenant roles on the shared mounts                                  |
| pki          | `sys/mounts/pki-platform`, `pki-platform/roles/<code>-*`, `pki-platform/issue/<code>-*`                                                    | Management of tenant leaf roles on the constrained leaf mount, and leaf issuance |
| cross tenant | `pki-downstream/root/sign-intermediate`                                                                                                    | Grants registered one by one, each with an explicit reason                       |

#### Item E.3 Assignment Scopes

1. Each rule which writes auth roles belongs to one assignment scope.
2. An assignment scope admits `default`, `registry-reader-<code>`, and the assignable policies which name the scope.
3. Transit unseal policies stay in the owned scope, which contains the Kubernetes auth mounts used by the Downstream Vault pods.
4. `pki-spire-signer-<code>` stays in the approle scope, which contains the AppRole of the SPIRE Parent upstream authority.
5. The gitlab scope admits neither a signer policy nor an issuer policy, because a CI job role carries claims which the tenant chooses.
6. `registry/<code>/bastion` publishes the policy names of each scope in the field `assignable_policies`.

| Scope   | Applicable Paths                                     | Assignable Policies                                                                            |
| ------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| owned   | `auth/<code>-*`                                      | `default`, `registry-reader-<code>`, `pki-platform-issuer-<code>`, `transit-unseal-<consumer>` |
| approle | `auth/approle/role/<code>-*`                         | `default`, `registry-reader-<code>`, `pki-spire-signer-<code>`                                 |
| gitlab  | `auth/gitlab-saas-ci-job-jwt-provider/role/<code>-*` | `default`, `registry-reader-<code>`                                                            |

### Item F. L3 Component Operator

1. A component operator is the Terraform identity of one mp component after the Downstream Vault is established.
2. A component operator logs in to the Downstream Vault with a SPIRE JWT-SVID.
3. A component operator does not hold any identity on the Bastion Vault.
4. An mp layer which changes a resource on the Bastion Vault runs through the platform-foundation Proxy, as listed in Item D.4.

### Item G. L4 Workload

Workload identities are declared by mp. Permissions on the Bastion side originate from the assignable policies of Item E.3.

| Workload                         | Authentication Method              | Policy                       | Bindings                                                                                     |
| -------------------------------- | ---------------------------------- | ---------------------------- | -------------------------------------------------------------------------------------------- |
| SPIRE Parent upstream authority  | Shared AppRole mount               | `pki-spire-signer-<code>`    | Secret ID and token bound to the address of the SPIRE Parent node on `vault-bastion-publish` |
| Transit seal of Downstream Vault | Tenant owned Kubernetes auth mount | `transit-unseal-<consumer>`  | `vault` ServiceAccount in the `vault` namespace, dedicated audience, `token_bound_cidrs`     |
| cert-manager of Downstream Vault | Tenant owned Kubernetes auth mount | `pki-platform-issuer-<code>` | Tenant leaf role of the Vault listener on `pki-platform`                                     |

The migration of the SPIRE Parent and the Downstream Vault to these policies is listed in Section 10 Item B.

### Item H. Policies Held by pgg

pgg declares five categories of policies. The tenant cannot rewrite these policies, because the tenant ACL does not grant any write on `sys/policies/acl`.

| Policy                             | Allowed Paths                                                                                                                                     | Holder                                 |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| `transit-unseal-<consumer>`        | Updates on `transit-unseal/encrypt/<key>`, `transit-unseal/decrypt/<key>`, and `auth/token/renew-self`                                            | Auto unsealing Vault clusters          |
| `registry-reader-<code>`           | Reads on `registry/data/<code>/*`, `registry/data/platform/*`, and `sys/internal/ui/mounts/registry`                                              | Tenant cert role and tenant workloads  |
| `pki-spire-signer-<code>`          | Updates on `pki-spire/root/sign-intermediate`                                                                                                     | SPIRE Parent upstream authority        |
| `pki-platform-issuer-<code>`       | Updates on `pki-platform/issue/<code>-*` and `pki-platform/sign/<code>-*`                                                                         | cert-manager of the Downstream Vault   |
| `gitlab-ci-code-reviewer-read`     | Reads on `secret/data/parent-group-governance/ci/*`                                                                                               | Automated code reviewer GitLab CI jobs |
| `operator-governance`              | Reads on the state backend token and the group keys of the governance identity                                                                    | Governance cert role                   |
| `operator-parent-group-governance` | Management of every mount, auth method, audit device, and policy of `foundation-vault-bastion`, and the KV paths below `parent-group-governance/` | Foundation cert role                   |
| `operator-service-admin-passwords` | Reads and writes on the paths of `service_admin_passwords` alone                                                                                  | Rotation cert role                     |

## Section 4. Root of Trust and Fact Publication

### Item A. Platform Trust Facts

This section addresses T6 from Section 2 Item C. Platform trust facts govern the permitted and excluded scopes of Name Constraints. Any unreviewed modification is equivalent to relaxing certificate trust boundaries.

`foundation-vault-bastion/trust-platform-facts.tf` reads the instance values from `secret/parent-group-governance/platform-trust` on the Bastion Vault. The instance values do not reside in the repository, since the repository is public and serves every deployment.

| Field                          | Source                | Example                                           | Purpose                                                                                                               |
| ------------------------------ | --------------------- | ------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `domain_suffix`                | Bastion KV            | `example.internal`                                | Platform domain, permitted DNS scope for `pki-downstream` and `pki-platform`                                          |
| `stages`                       | Bastion KV, JSON list | `["production"]`                                  | Derivation of the SPIRE trust domain, formatted as `<stage>.<domain_suffix>`                                          |
| `network_cidr`                 | Bastion KV            | `10.20.0.0/16`                                    | Platform network CIDR, permitted IP scope for `pki-downstream` and `pki-platform`                                     |
| `bastion_publish_cidr`         | Bastion KV            | `10.20.0.0/24`                                    | Bastion publish network CIDR, excluded IP scope, and the source of the Bastion publish address in `token_bound_cidrs` |
| `downstream_extra_dns_domains` | Code constant         | `hubble-grpc.cilium.io`, `hubble-relay.cilium.io` | Fixed suffixes under which Cilium names Hubble mTLS peers                                                             |
| `kubernetes_cluster_domain`    | Code constant         | `cluster.local`                                   | Permitted DNS scope for `pki-platform`, which covers the Service names of in-cluster raft peers                       |

1. The instance values MUST reside in `secret/parent-group-governance/platform-trust`, which only the root token writes.
2. `platform-trust.example.json` documents the fields with example values. Git ignores the instance file `platform-trust.json`.
3. tfvars, `-var`, and `TF_VAR_` MUST NOT be able to override platform trust facts.
4. `terraform_data.platform_trust_validation` carries a precondition which stops the plan when a field is missing or malformed, when `stages` is empty, or when `bastion_publish_cidr` lies outside `network_cidr`.
5. A `check` block is not used for the validation, because a failed `check` assertion only produces a warning (refer to the [Terraform check block documentation](https://developer.hashicorp.com/terraform/language/block/check)).
6. KV v2 keeps every version of the path. A change of the instance values replaces the constrained intermediate certificates in the next plan, which exposes the change during review of the plan.
7. `bastion_vault.publish_address` of `workstation-topology.yaml` declares the Bastion publish address, and a precondition of `terraform_data.platform_trust_validation` stops the plan when the address lies outside `bastion_publish_cidr`.

### Item B. Intermediate CAs Restricted by Name Constraints

This section addresses T7, T8, and T16 from Section 2 Item C. The trust bundles of both the workstation and platform nodes trust `pki-root`, accepting any certificate which chains back to `pki-root`. When an intermediate CA lacks Name Constraints, the blast radius of a compromised subordinate CA extends to the entire trust domain of `pki-root`.

#### Item B.1 PKI Hierarchy

| Mount              | Issuer      | Purpose                                                                                                                  | `max_path_length` |
| ------------------ | ----------- | ------------------------------------------------------------------------------------------------------------------------ | ----------------- |
| `pki-root`         | Self-signed | Infrastructure Root CA, `prevent_destroy`                                                                                | Unlimited         |
| `pki-intermediate` | `pki-root`  | Bootstrap Issuing Intermediate without Name Constraints, on which tenants do not hold any grant                          | 0                 |
| `pki-spire`        | `pki-root`  | Target issuer of the SPIRE Parent CA, which in turn signs the SPIRE Child CA, with the migration in Section 10 Item B    | 2                 |
| `pki-downstream`   | `pki-root`  | Target issuer of the Downstream Vault CA, which in turn signs one mesh CA layer, with the migration in Section 10 Item B | 2                 |
| `pki-platform`     | `pki-root`  | Leaf issuer for tenant roles, such as the listener certificates of the SPIRE Parent and the Downstream Vault             | 0                 |

pgg embeds the Name Constraints of `pki-spire`, `pki-downstream`, and `pki-platform` into the intermediate CA certificates through `root/sign-intermediate` on `pki-root`. Subordinate callers cannot omit or loosen these restrictions.

Every intermediate mount holds an ECDSA P-256 key. `pki-root` holds an ECDSA P-384 key and expires on 2035-12-31. Section 7 Item H records the measurements and the trade-offs of the key algorithms.

#### Item B.2 Constraint Details

| Mount            | Permitted                                                              | Excluded                                                              |
| ---------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------- |
| `pki-spire`      | DNS and URI: SPIRE trust domain                                        | All IPv4 and IPv6                                                     |
| `pki-downstream` | DNS `domain_suffix` and Hubble names, IP `network_cidr`                | IP `bastion_publish_cidr`, URI `domain_suffix` and `.<domain_suffix>` |
| `pki-platform`   | DNS `domain_suffix` and `kubernetes_cluster_domain`, IP `network_cidr` | IP `bastion_publish_cidr`, URI `domain_suffix` and `.<domain_suffix>` |

1. `pki-spire` excludes all IP addresses, preventing certificates issued by SPIRE from spoofing Bastion addresses `127.0.0.1` or `10.20.0.1`.
2. `pki-downstream` excludes URIs under the platform domain and every subdomain of the platform domain, a range which contains the SPIFFE trust domain, preventing the Downstream Vault from issuing SVIDs.
3. `pki-downstream` excludes the Bastion publish CIDR, ensuring that a compromised Downstream Vault cannot issue listener certificates for the Bastion Vault.
4. `pki-platform` permits neither a loopback address nor the Bastion publish CIDR, and a tenant leaf role therefore cannot issue a Bastion listener certificate.
5. The Downstream Vault listener certificate MUST NOT carry `localhost` or `127.0.0.1`.
6. The raft peers of the Downstream Vault MUST join through names under `kubernetes_cluster_domain`.
7. `pki-intermediate` carries a zero path length, which keeps the mount from signing a CA.

#### Item B.3 SAN Requirements for Subordinate CAs

1. When the issuing CA carries Name Constraints, the certificate issued through `root/sign-intermediate` MUST carry at least one SAN.
2. A CSR lacking a SAN is rejected by Vault with the error: `issuer has name constraints but leaf doesn't have a SAN extension`.
3. With `use_csr_values = false`, Vault takes the SANs from the `alt_names`, `ip_sans`, and `uri_sans` request parameters instead of the CSR. Whether the SPIRE Vault upstream authority plugin supplies `uri_sans` MUST be verified during the SPIRE Parent migration.
4. The intermediate CA of the Downstream Vault MUST include DNS names within the permitted scope in `alt_names`, and cannot rely solely on `exclude_cn_from_sans`.

### Item C. Registry

This section addresses T4 and T5 from Section 2 Item C. The choice of publication channel simultaneously dictates what data readers can view and whether readers can modify the values they consume.

#### Item C.1 Publication Contents

`foundation-vault-bastion/service-registry.tf` declares the KV v2 mount `registry` along with two types of publications. Each field of `registry/<code>/bastion` holds one JSON object. In `registry/platform/trust`, `spire_trust_domains` holds a JSON array, and the remaining fields hold plain strings.

| Path                      | Field                                                                          | Contents                                                                                                                  |
| ------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `registry/platform/trust` | `domain_suffix`, `spire_trust_domains`, `network_cidr`, `bastion_publish_cidr` | Platform trust facts from Item A                                                                                          |
| `registry/<code>/bastion` | `vault`                                                                        | Bastion endpoint and listener CA PEM                                                                                      |
| `registry/<code>/bastion` | `pki`                                                                          | Root CA PEM, and the mount path, the certificate, and the assignable policy of each constrained mount owned by the tenant |
| `registry/<code>/bastion` | `transit_unseal`                                                               | Transit mount path, and the key and policy names owned by the tenant                                                      |
| `registry/<code>/bastion` | `assignable_policies`                                                          | Assignable policy names of each assignment scope from Section 3 Item E.3                                                  |

#### Item C.2 Access Rules

1. Only `foundation-vault-bastion` of pgg MAY write to `registry`.
2. The publication path MUST NOT fall under the tenant writable path `secret/<code>/`. A tenant able to write a publication location could loosen the facts which constrain the tenant.
3. Tenants consume publication content using `registry-reader-<code>`.
4. Consumers read data via data source `vault_generic_secret`, decode JSON fields with `nonsensitive(jsondecode(...))`, and read plain string fields with `nonsensitive(...)`.
5. Consumers MUST inspect the read fields using preconditions.
6. The registry is not permitted to publish secret IDs, role IDs, or any private keys.

### Item D. Transit Unseal on the Bastion Side

This section addresses T9 and T10 from Section 2 Item C. Decrypt permissions on a transit key, together with the encrypted root key in the Downstream Vault storage, are equivalent to the unseal capability of the Downstream Vault.

1. `foundation-vault-bastion/service-transit-unseal.tf` declares the mount `transit-unseal`, isolated from PKI mounts.
2. Each auto-unsealing Vault cluster maintains a dedicated `aes256-gcm96` key.
3. Both `exportable` and `allow_plaintext_backup` remain false on keys. Neither setting can return to false once enabled.
4. `deletion_allowed` remains false on keys.
5. Policy `transit-unseal-<consumer>` permits only encrypt, decrypt, and `auth/token/renew-self` on that specific key.
6. The Kubernetes auth role on the consumer side is declared by mp, configured with `token_no_default_policy = true`, `token_period = 3600`, and `token_bound_cidrs`.

## Section 5. Audit and Alerts

This section addresses T11 and T12 from Section 2 Item C. Vault does not raise alerts on audit events. Detection therefore relies on periodic evaluation of the audit log.

### Item A. Audit Devices

1. `foundation-vault-bastion/audit.tf` enables two file-based audit devices.
2. The `file` device writes to `/opt/vault/audit/audit.log`, mapped to `parent-group-governance/vault/audit` on the host, with mode `0600`.
3. The `stdout` device passes through container logging into journald.
4. Vault processes requests as long as either device can accept writes, failing requests only when both devices become unreachable.

### Item B. Detection Rules

`workstation_vault_audit` installs `vault-audit-check.timer` in the systemd user manager of the operator account, executing `vault_audit_check.py` every 5 minutes by default.

1. Prior to execution, logrotate rotates logs exceeding 100MB and preserves 14 copies.
2. The script records the inode and read offset of the log file, consuming any remainder in `audit.log.1` after a rotation occurs.
3. The script inspects only records with `type` equal to `response`.
4. Every finding is written to the systemd journal via `logger --priority auth.alert --tag vault-audit-alert`.

| Rule                              | Trigger Condition                                                                                                                      |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Transit key management            | Any path under `transit-unseal/` other than encrypt and decrypt                                                                        |
| Transit failure                   | Requests under `transit-unseal/` carrying an error                                                                                     |
| Transit source                    | Source address of an encrypt or decrypt request outside `workstation_vault_audit_transit_source_cidrs`, skipped when the list is empty |
| Audit modification                | Writes targeting `sys/audit*`                                                                                                          |
| root token                        | `auth.policies` containing `root`                                                                                                      |
| Denied privilege escalation write | Denied writes targeting `sys/policies/acl/` or `role`, `users`, `groups`, `certs` under auth mounts                                    |

### Item C. Accessors and HMAC

1. The detection rules rely only on `request.path`, `request.operation`, `request.remote_address`, `error`, and `auth.policies`, which the Bastion audit log records in plaintext. Vault hashes most other string values (refer to [Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)).
2. Token accessors are HMAC-hashed by default according to `hmac_accessor = true` (refer to the [Vault audit API](https://developer.hashicorp.com/vault/api-docs/system/audit)).
3. The `accessor=` output in alert messages represents an HMAC hash value and must be resolved through `sys/audit-hash` when correlating.
4. Because an accessor can be used to look up or revoke tokens, `./governance` does not output raw accessors to the terminal.

## Section 6. governance CLI

### Item A. Package Architecture

| Package or role                        | File                                      | Responsibility                                                                                                        |
| -------------------------------------- | ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `internal/topology`                    | `topology.go`                             | Loads `bastion_vault` of `workstation-topology.yaml`, the Bastion endpoint and the listener certificate addresses     |
| `internal/vaultops`                    | `vaultops.go`, `vaultops_tls.go`          | Vault lifecycle and the local CA, with the endpoint and the listener addresses of the topology alone                  |
| `pkg/secretrotate`                     | `factory_default.go`                      | `AwaitFactoryDefault`, which `vault init` uses to verify that each service still accepts its factory default          |
| `cmd/governance`                       | `operations.go`, `commands.go`, `menu.go` | `host apply-all` and the first menu item, which run SELinux, libvirt, the local CA when absent, and the Vault Proxies |
| Ansible role `workstation_vault_proxy` | `tasks/`, `templates/`                    | Client certificates, Proxy configurations, systemd user units, and `vault-proxy-env`                                  |

### Item B. Commands and Menus

1. `./governance host apply-all` and the first menu item `[Host] Apply All Workstation Prerequisites` prompt for the become password once.
2. `./governance host apply-vault-proxy` and the menu item `[Host] Apply Workstation Vault Proxies` run the Proxy role alone.
3. The CLI injects the operator account and the local CA directory `vault/tls` into the Proxy role.

### Item C. Behavioral Guarantees

1. `./governance` removes every Vault variable which the Vault API client reads, such as `VAULT_ADDR`, `VAULT_CACERT`, and `VAULT_SKIP_VERIFY`, before any command runs. The Vault API client reads the process environment inside `NewClient`, and an ambient value therefore overrides or breaks an explicitly configured client. Without the removal, a stale `VAULT_CACERT` of a wiped TLS directory stops the CLI which regenerates the TLS directory, and the Proxy environment of a `.envrc` reroutes the root operations of the CLI to a Proxy. Every test package which builds a Vault client clears the same variables in `TestMain`.
2. `./governance vault init` sends no Vault request when a service of `service_admin_passwords` rejects its factory default password.
3. `./governance host apply-all` generates the local CA only when `vault/tls/ca.pem` is absent, since a new CA invalidates the listener certificate, every client certificate of the Proxies, and every operator cert role.
4. A blank answer to the become password prompt cancels the run before any playbook starts.

### Item D. Testing

| File                                                                    | Tests                      | Coverage                                                                                                  |
| ----------------------------------------------------------------------- | -------------------------- | --------------------------------------------------------------------------------------------------------- |
| `internal/topology/topology_test.go`                                    | `TestLoad_*`               | Endpoint and listener addresses of the topology, rejection of an incomplete `bastion_vault`, missing file |
| `internal/vaultops/vaultops_tls_test.go`                                | `TestGenerateTLS*`         | Chain validity, subject alternative names of the topology, refusal without listener addresses, key types  |
| `pkg/secretrotate/factory_default_test.go`                              | `TestAwaitFactoryDefault*` | Waiting for the service, the retained state verdict, and a credential without a factory default           |
| `cmd/governance/menu_test.go`                                           | `TestBuildMenuOptions_*`   | Apply All first, Quit last, each host step alone, and the service admin password labels                   |
| `ansible/roles/workstation_vault_audit/tests/test_vault_audit_check.py` | 20 pytest test cases       | 6 detection rules, log rotation and truncation, state persistence                                         |

Tests utilize httptest to simulate the Bastion Vault and the services of `service_admin_passwords`.

## Section 7. Trade-offs in Section 2 Item C

### Item A. Tenant ACL Declared by pgg

For risks associated with rejecting this choice, refer to T1 and T2.

1. Constraint: Vault OSS does not restrict policy content, and a tenant which writes both policies and roles can obtain arbitrary privileges.
2. Decision: pgg declares the tenant ACL and every assignable policy. A tenant does not write or request any policy.
3. Cost: A new Bastion permission for a tenant requires a pgg change and a pgg apply.

| Alternative                                                    | Rationale for Rejection                                                                                                  |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Tenant writes policies with the tenant prefix                  | A prefix does not restrict the capabilities inside a policy                                                              |
| A broker validates and writes policies which a tenant requests | Every request change requires an mp apply followed by a pgg apply, and the request scope checks grow with every new path |

### Item B. Operator Login Mechanism

For risks associated with rejecting this choice, refer to T3, T13, T14, and T15.

1. Constraint: Every non-root operator needs a Bastion Vault login for Terraform, Ansible, and the Vault CLI, and a credential issued by Terraform enters the pgg state.
2. Decision: One Vault Proxy per operator identity logs in with a client certificate through cert auth, holds the token in memory, and admits only callers presenting the client certificate of the identity.
3. Cost: The client private key is a long lived credential on the operator workstation. The local CA key signs a client certificate for any identity. The certificates expire after 365 days, and a run of the Proxy role within 30 days of expiry renews the certificates.
4. Rejected alternatives and rationales are summarized in the table below:

| Alternative                                                   | Rationale for Rejection                                                                                               |
| ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| Terraform issues secret IDs and writes them to KV and outputs | Secret IDs never expire and persist in state files                                                                    |
| A wrapped AppRole secret ID per sub-shell session             | The token lives in the shell environment, every session needs the root token, and editors and direnv lose the session |
| A token role session per owner code                           | The token lives in the shell environment, and the role needs `allowed_entity_aliases = ["*"]`                         |
| The `api_proxy` stanza of Vault Agent                         | HashiCorp deprecated the stanza in favor of Vault Proxy                                                               |

### Item C. Fact Publication Channel

For risks associated with rejecting this choice, refer to T4 and T5.

1. Constraint: `terraform_remote_state` downloads the complete state snapshot. Consumers require GitLab tokens with read access to the pgg project, and the Maintainer role confers write access.
2. Decision: pgg publishes facts to the `registry` mount, and tenants read the facts through Vault ACLs.
3. Cost: Consumers must hold a Vault token. KV values are stored as strings, which consumers decode and validate independently.

| Alternative                                         | Rationale for Rejection                                                                        |
| --------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Retaining `terraform_remote_state`                  | Consumers acquire complete state snapshots and require GitLab tokens for the pgg project       |
| Reading state with a Developer-role read-only token | Consumers still acquire complete state snapshots                                               |
| Consul KV                                           | Requires deploying stateful services and bootstrapping ACLs, introducing another root of trust |
| SSM Parameter Store                                 | Coupled with AWS, incompatible with on-prem and Nutanix migration                              |
| Publishing to `secret/<code>/`                      | Writable by the tenant, allowing the tenant to relax the constraints placed on the tenant      |

Terraform documentation recommends publishing external data outside state files to maintain decoupled access controls (refer to [The terraform_remote_state Data Source](https://developer.hashicorp.com/terraform/language/state/remote-state-data)).

### Item D. Platform Trust Facts Declaration Mechanism

For risks associated with rejecting this choice, refer to T6.

1. Constraint: The repository is public and serves every deployment. Git ignores `*.tfvars`, and a `variable` yields to `-var` and `TF_VAR_`.
2. Decision: The instance values reside in the Bastion KV, which only the root token writes and which keeps every version.
3. Cost: A greenfield deployment writes the KV entry once before the first apply. A change of the instance values is reviewed through the KV version history and the plan diff instead of a merge request.

| Alternative                     | Rationale for Rejection                                                             |
| ------------------------------- | ----------------------------------------------------------------------------------- |
| Locals or a committed data file | Publishes the instance values of a deployment in a public repository                |
| tfvars                          | Changes bypass peer review and can relax Name Constraints locally                   |
| `variable` with defaults        | Can be overridden via `-var`, `TF_VAR_`, and `*.auto.tfvars` without leaving a diff |
| Declared by mp and read by pgg  | Allows the constrained party to define its own constraints                          |

### Item E. Enforcement Point of Name Constraints

For risks associated with rejecting this choice, refer to T7 and T8.

1. Constraint: Constraint parameters for `root/sign-intermediate` are supplied by the caller, and the caller can omit the parameters.
2. Decision: pgg declares dedicated constrained intermediate mounts, baking restrictions directly into intermediate CA certificates to cover the entire subordinate tree.
3. Cost: Introducing a new category of subordinate CA requires pgg to configure an additional mount.

### Item F. Assignment Scope Partitioning

For risks associated with rejecting this choice, refer to T9 and T17.

1. Constraint: A tenant chooses the claims and the sources of a role on the shared AppRole and GitLab CI JWT mounts.
2. Decision: Three assignment scopes admit only the policies which the workloads of each mount class need.
3. Cost: `auth/<code>-*` covers every auth mount type which a tenant creates, and the owned scope therefore cannot distinguish Kubernetes auth from JWT auth.

### Item G. CLI Output and Exit Status

For risks associated with rejecting this choice, refer to T11.

1. Accessors are omitted from output, as justified in Section 5 Item C.

### Item H. Key Algorithm of Intermediate CAs

1. Constraint: A mount generates the key of an intermediate CA once per rotation. The key signs only the certificates which the mount issues. The Bastion Vault signs at the rotation rate of the SPIRE Parent CA, the Downstream Vault CA, and a few listener certificates. The Downstream Vault and SPIRE sign at the request rate of tenants.
2. Decision: Every intermediate CA of the Bastion Vault holds an ECDSA P-256 key. The key name carries the key type, because Vault rejects a new key under an existing key name. The listener CA and the listener certificate which `./governance vault tls-generate` generates also hold ECDSA P-256 keys, stored as PKCS #8.
3. Cost: A change of the key type replaces each intermediate CA and every certificate below the intermediate CA.
4. Rejected alternative: Ed25519 provides the same security strength as P-256. Major browsers do not accept an Ed25519 signature in a TLS certificate chain, and the ecosystem support of Ed25519 is narrower than the support of P-256.

The following measurements ran with `openssl speed -seconds 1` of OpenSSL 3.5.8 on one core of the operator workstation on 2026-10-04.

| Algorithm   | Key Generation   | Signatures per Second | Verifications per Second |
| ----------- | ---------------- | --------------------- | ------------------------ |
| RSA 2048    | 25 ms            | 2,765                 | 93,528                   |
| RSA 4096    | 278 ms to 310 ms | 403                   | 24,849                   |
| ECDSA P-256 | Not measured     | 77,360                | 23,170                   |
| Ed25519     | Not measured     | 47,162                | 17,118                   |

1. The intermediate key algorithm does not limit the tenant count of the Bastion Vault. The Bastion Vault signs a few certificates per rotation, and one core signs 403 RSA 4096 signatures per second.
2. A TLS handshake verifies the chain. RSA verifies faster than ECDSA, and an RSA key in the chain therefore does not slow a handshake.
3. A Vault role which generates the leaf key through `issue` spends the key generation cost on every request. RSA 4096 limits one core to about three leaf keys per second. The roles of the Downstream Vault MUST therefore use ECDSA P-256. A `sign` request carries a key from the client, and the request does not spend the key generation cost in Vault.
4. NIST SP 800-57 Part 1 assigns 128 bits of security strength to both P-256 and RSA 3072. RSA 2048 provides 112 bits.
5. NIST IR 8547 initial public draft Table 2 deprecates digital signatures of 112 bits after 2030. Table 2 disallows every quantum vulnerable digital signature, ECDSA and EdDSA included, after 2035.
6. `pki-root` holds an ECDSA P-384 key at 192 bits of security strength, and `not_after` ends the root on 2035-12-31. The root therefore stays above the 112 bit level which item 5 deprecates, and the root expires before the disallowance date. The root replaced an RSA 2048 root with a TTL of 10 years, which would have served past both dates.
7. The root drops `prevent_destroy` for the one apply which replaces the root, and the layer restores `prevent_destroy` after the apply.

## Section 8. Deployment Order

### Step A. Greenfield Deployment

1. Run the first menu item `[Host] Apply All Workstation Prerequisites` of `./governance`, which applies SELinux, the libvirt prerequisites, the local CA when absent, and the Vault Proxies.
2. Start the Bastion Vault container from `compose.yml`, which declares the audit volume, together with every service of `service_admin_passwords`.
3. Initialize the Bastion Vault, unseal the Bastion Vault, and enable the KV v2 engine through `./governance`.
4. Write the instance values with `vault kv put secret/parent-group-governance/platform-trust @platform-trust.json`, using `platform-trust.example.json` as the template.
5. Apply `foundation-vault-bastion` with `vault-proxy-env root`. The apply creates the operator cert roles, after which every Proxy logs in.
6. Execute the `workstation_vault_audit` playbook, passing `workstation_vault_audit_home`.
7. Run the mp layers which require the Bastion Vault through the platform-foundation Proxy, following the sequence documented in `architecture_platform-foundation_deployment-chain.md` in the planning repository.
8. Revoke the root token with `./governance vault revoke-root` once the foundation Proxy logs in.

### Step B. Routine Operations

1. Execute `./governance vault unseal` after any Bastion Vault reboot.
2. Enter a directory whose `.envrc` loads the operator identity, and direnv loads the Proxy environment.
3. Run `./governance host apply-vault-proxy` within 30 days of the expiry of the client certificates.
4. Generate plans for Terraform changes using `terraform plan -out=tfplan`, reviewing the plans before executing `terraform apply tfplan`.

## Section 9. Verification

### Step A. Codebase Verification

```bash
cd tools/governance
go vet ./...
golangci-lint run ./...
go test -race -count=1 ./...
go test -count=1 -coverprofile=coverage.out ./...
cd -
PYTHONDONTWRITEBYTECODE=1 uv run --no-project --with pytest --with pytest-cov pytest -q -p no:cacheprovider ansible/roles/workstation_vault_audit/tests
terraform -chdir=terraform/layers/foundation-vault-bastion validate
```

`./build-governance.sh` executes Go tests, Python tests, SonarQube scanning, and CLI compilation in order.

### Step B. Vault Proxy Verification

Execute the following commands in a shell of `platform-foundation`, whose `.envrc` loads the identity `platform-foundation`:

```bash
echo "VAULT_TOKEN=${VAULT_TOKEN}"
vault token lookup -format=json | jq '{path: .data.path, policies: .data.policies, ttl: .data.ttl, bound_cidrs: .data.bound_cidrs}'
vault policy list
curl -s -o /dev/null -w '%{http_code}\n' --cacert "$VAULT_CACERT" "$VAULT_ADDR/v1/sys/health"
systemctl --user is-active vault-proxy@platform-foundation.service
```

| Command                           | Expected Result                                                                                                                                                                                         |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Token check                       | `VAULT_TOKEN=proxy-supplied`, the placeholder which the Proxy overwrites                                                                                                                                |
| `vault token lookup`              | `path` is `auth/operator-cert/login`, policies are `default`, `platform-foundation-terraform-operator`, `registry-reader-platform-foundation`, `ttl` does not exceed 3600, `bound_cidrs` is `127.0.0.1` |
| `vault policy list`               | 403 permission denied                                                                                                                                                                                   |
| `curl` without client certificate | `000`, since the Proxy listener rejects the handshake                                                                                                                                                   |
| Unit state                        | `active`                                                                                                                                                                                                |

### Step C. Registry and Privilege Boundary Verification

Execute the following commands in the same shell as Step B:

```bash
vault kv get -format=json registry/platform-foundation/bastion | jq '.data.data | keys'
vault kv get -field=spire_trust_domains registry/platform/trust
vault kv put registry/platform-foundation/bastion x=y
vault write auth/approle/role/platform-foundation-scope-test token_policies=transit-unseal-platform-foundation-vault-downstream
vault write auth/gitlab-saas-ci-job-jwt-provider/role/platform-foundation-scope-test token_policies=pki-spire-signer-platform-foundation
vault write pki-intermediate/roles/platform-foundation-scope-test allow_any_name=true
vault kv metadata get secret/platform-foundation/terraform/approle
```

| Command                                                     | Expected Result                                                           |
| ----------------------------------------------------------- | ------------------------------------------------------------------------- |
| Read `registry/platform-foundation/bastion`                 | Fields are `assignable_policies`, `pki`, `transit_unseal`, `vault`        |
| Read `registry/platform/trust`                              | `["production.example.internal"]`                                         |
| Write to registry                                           | 403 permission denied                                                     |
| Assign transit unseal policy on shared AppRole mount        | 403 permission denied, and triggers a `denied policy or role write` alert |
| Assign `pki-spire-signer-<code>` on the GitLab CI JWT mount | 403 permission denied, and triggers a `denied policy or role write` alert |
| Create a tenant role on `pki-intermediate`                  | 403 permission denied                                                     |
| Legacy approle KV                                           | `No value found`                                                          |

### Step D. Name Constraints Verification

Verification of Name Constraints comprises two parts. The first verifies that Vault rejects non-compliant names during issuance. The second simulates a compromised intermediate CA private key, using locally signed leaf certificates to confirm that `openssl verify` rejects non-compliant names. The following commands run using the root token. The test CA has a TTL of 1 hour and MUST be revoked after verification concludes.

```bash
# The names and addresses inside the test certificates are examples. vault-proxy-env root prints the listener and CA.
eval "$(vault-proxy-env root)"
vault read -field=certificate pki-root/cert/ca > root.pem
vault read -field=certificate pki-spire/cert/ca > inter.pem

openssl req -new -newkey rsa:2048 -nodes -keyout test-ca.key -subj "/CN=nc-test.production.example.internal" -out test-ca.csr
vault write -format=json pki-spire/root/sign-intermediate csr=@test-ca.csr \
  common_name=nc-test.production.example.internal exclude_cn_from_sans=true \
  uri_sans=spiffe://production.example.internal/nc-test ttl=1h > test-ca.json
jq -r .data.certificate test-ca.json > test-ca.pem

openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=nc-leaf" -out leaf.csr
printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:10.20.0.1\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA test-ca.pem -CAkey test-ca.key -CAcreateserial -days 1 -extfile leaf.ext -out leaf.pem
cat test-ca.pem inter.pem > chain.pem
openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem

vault write pki-spire/revoke serial_number="$(jq -r .data.serial_number test-ca.json)"
unset VAULT_ADDR VAULT_CACERT TF_HTTP_USERNAME TF_HTTP_PASSWORD
```

The expected output of `openssl verify` for non-compliant names is `excluded subtree violation` or `permitted subtree violation`. Swapping `subjectAltName` with names from the table below allows testing additional scenarios:

| Mount            | Expected Pass                                                                                      | Expected Rejection                                                                                                      |
| ---------------- | -------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `pki-spire`      | `URI:spiffe://production.example.internal/ns/a/sa/b`                                               | `URI:spiffe://evil.example/ns/a`, `IP:10.20.0.1`, `IP:127.0.0.1`, `DNS:localhost`                                       |
| `pki-downstream` | `DNS:keycloak.production.example.internal,IP:10.20.130.250`, `DNS:a.default.hubble-grpc.cilium.io` | `IP:10.20.0.1`, `IP:127.0.0.1`, `DNS:localhost`, `DNS:gitlab.com`, `URI:spiffe://production.example.internal/ns/a/sa/b` |

The test CA for `pki-downstream` does not have a URI SAN. The request MUST supply `alt_names=nc-test.example.internal` instead. Experimental results recorded on 2026-10-03 are as follows:

| Item                                                             | Result                                                                                                                            |
| ---------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Vault rejects non-compliant names during issuance                | `pki-spire` Bastion IP and external DNS, and `pki-downstream` `localhost`, Bastion IP, and SVID, all 5 items rejected             |
| Subordinate self-signed leaf certificates under `pki-spire`      | 1 expected pass succeeded, 4 expected rejections were all rejected                                                                |
| Subordinate self-signed leaf certificates under `pki-downstream` | 2 expected passes succeeded, 5 expected rejections were all rejected                                                              |
| Path length                                                      | Test CA `pathlen` decrements from 2 to 1. Scenarios exceeding path limits remain untested                                         |
| `pki-platform` issuance through a tenant role on 2026-10-04      | 2 expected passes succeeded. Vault rejected `localhost`, `127.0.0.1`, the Bastion publish address, `gitlab.com`, and a SPIFFE URI |
| `pki-platform` subordinate CA on 2026-10-04                      | The CA certificate carries `pathlen:0`, and a tenant call on `root/sign-intermediate` returned 403                                |

### Step E. Secret Scanning on State Files

The following command prints only the length of sensitive attributes, never their values:

```bash
cd terraform/layers/foundation-vault-bastion
terraform state pull | python3 -c '
import json, sys
state = json.load(sys.stdin)
for res in state["resources"]:
    for inst in res["instances"]:
        for path in inst.get("sensitive_attributes", []):
            name = path[0]["value"]
            value = inst["attributes"].get(name)
            print(res["type"], res["name"], inst.get("index_key", ""), name, len(json.dumps(value)) if not isinstance(value, str) else len(value))
'
```

In the expected output, only `data_json` of `registry_platform_trust` and `registry_tenant_bastion` contains data, representing the public facts detailed in Section 4 Item C. The data source `vault_generic_secret.platform_trust` also contains data, representing the platform trust facts of Section 4 Item A. All other sensitive attributes MUST be `null`.

### Step F. Alerts

```bash
journalctl --user -t vault-audit-alert --since today
systemctl --user list-timers vault-audit-check.timer
```

Root token usage and rejected role writes MUST appear in the systemd journal.

## Section 10. Residual Risks and Next Steps

### Item A. Residual Risks

1. `vault/keys/unseal.key` holds every unseal key, and a reader of the file produces a root token through generate-root, which `enable_unauthenticated_access` admits without a token. A compromise of the workstation account therefore compromises the Bastion Vault, while the root token itself resides on disk during the bootstrap and a break-glass alone.
2. Audit logs lack a remote sink. A compromise of the host allows tampering with the audit logs.
3. Alerts are written only to journald without push notification channels, and the user timer requires systemd linger when the operator is not logged in.
4. The owned scope of `auth/<code>-*` covers JWT auth mounts created by the tenant.
5. `pki-intermediate` lacks Name Constraints. The zero path length keeps the mount from signing a CA, and tenants do not hold any grant on the mount.
6. `meta-gitlab-project` in mp still reads state from other pgg layers. mp therefore still requires a GitLab token with read privileges on the pgg project.
7. `workstation-topology.yaml` declares the Bastion publish address, while `bastion_publish_cidr` of the platform trust facts declares the publish network. A precondition ties both, and the two values remain two declaration sources.
8. The client private key of each operator identity resides below `~/.config/vault-proxy` with mode `0600`. A process of the operator account reads the key and logs in as the identity until the certificate expires.
9. `vault/tls/ca-key.pem` signs a client certificate for any operator identity, hence the key is equivalent to every operator identity. The file carries mode `0600`.
10. Every classical signature of the hierarchy, ECDSA P-384 included, is quantum vulnerable. NIST IR 8547 initial public draft disallows quantum vulnerable signatures after 2035, and the root therefore MUST be replaced by a root of a quantum resistant algorithm before 2035-12-31.

### Item B. Next Steps

1. Rebuild mp to read `registry`, removing every `terraform_remote_state` reference to `foundation-vault-bastion`.
2. Move the SPIRE Parent upstream authority to `pki-spire`, the Downstream Vault intermediate CA to `pki-downstream`, and every listener certificate to `pki-platform`.
3. Integrate the secret scanning routine from Section 9 Step E into pgg CI pipelines.
4. Conduct verification testing for path length limit rejections when exceeding allowed CA tiers.
5. Consolidate the publish address of `workstation-topology.yaml` and `bastion_publish_cidr` into one declaration source.
6. Add an audit rule which alerts on writes to `secret/parent-group-governance/platform-trust`.
7. Move the remaining instance values of pgg, such as the backend addresses, the listener addresses, and the Ansible defaults, out of the repository.
