# Bastion Vault Privilege Convergence Architecture

This document records the privilege boundaries, roots of trust, fact publications, audits, and the supporting `./governance` CLI on the Bastion Vault for `parent-group-governance` (referred to below as pgg). The intended audience includes engineers maintaining pgg and `meta-platform` (referred to below as mp).

## Section 1. Scope and Terminology

### Item A. Scope

1.  This document covers two layers of pgg: `foundation-vault-bastion` and `group-vault-policy-broker`.
2.  This document covers packages and commands related to Bastion Vault privileges in `tools/governance`.
3.  This document covers the Ansible role `workstation_vault_audit`.
4.  How the mp side consumes the registry and tenant sessions is documented in `architecture_meta-platform_deployment-chain.md` within the planning repository; this document describes only the interface provided by pgg.

### Item B. Terminology Definitions

- **Bastion Vault**: The `hashicorp/vault:2.0` OSS instance running via podman compose on the operator workstation, listening on `127.0.0.1:8200` and `172.16.0.1:8200`.
- **Tenant**: A product repository granted a restricted set of privileges on the Bastion Vault, identified by an owner code; currently only `meta-platform`.
- **Owner Code**: An identifier string for a tenant, formatted as lowercase alphanumerics connected by hyphens, such as `meta-platform`, denoted as `<code>` below.
- **root token**: The Bastion Vault root token stored in `~/.vault-token`, held exclusively by the operator.
- **Tenant AppRole**: The AppRole role named `<code>-terraform-operator`, serving as the sole login entry point for a tenant prior to the establishment of SPIRE.
- **tenant session**: A sub-shell launched by `./governance` after logging in via the tenant AppRole, where the tenant token exists only in `VAULT_TOKEN` of that sub-shell.
- **broker**: The `group-vault-policy-broker` layer, which writes tenant ACL policies based on tenant requests.
- **Cap**: The set of policy names which an auth role of a tenant is allowed to assign.
- **registry**: The KV v2 mount `registry`, where pgg publishes facts needed by tenants; writable exclusively by pgg.
- **Name Constraints**: The certificate extension defined by RFC 5280 which restricts the names which certificates issued under a given CA certificate may carry.

## Section 2. Background, Threats, and Design Principles

### Item A. Protected Assets

1.  The issuance capabilities of `pki-root` and subordinate intermediate CAs. The trust bundles of both the workstation and platform nodes trust `pki-root`; an issuer able to produce a certificate chaining back to `pki-root` can impersonate any service which those trust bundles accept.
2.  The unseal capability of the Downstream Vault. Decrypt privileges on the transit key, combined with the encrypted root key in the Downstream Vault storage, yield the root key of the Downstream Vault, which is equivalent to acquiring all secrets inside the Downstream Vault.
3.  The authorization boundaries between tenants, as well as between tenants and pgg.
4.  Platform trust facts, specifically domains, SPIRE trust domains, and CIDR blocks. These values determine the permitted and excluded scopes of Name Constraints.
5.  Audit logs. The audit log serves as the sole ground truth for forensic analysis.

### Item B. Threat Sources

1.  Leaked tenant tokens or secret IDs, such as values lingering in terminal scrollback, process environments, or Terraform state files.
2.  Compromised mp layers, mp component operators, or CI jobs.
3.  Compromised private keys of the SPIRE CA or the Downstream Vault CA.
4.  Individuals or processes with read access to the Terraform state of the pgg project.
5.  Processes executing under the operator workstation account which were not initiated by the operator directly.
6.  Operator errors, such as relaxing constraints in local tfvars or executing commands in the wrong shell context.

### Item C. Threat Scenarios and Consequences

Each row in the table below represents a threat scenario. The unmitigated consequence column details what an attacker can achieve in the absence of controls, and the countermeasure column points to the corresponding section of this document.

| ID  | Scenario                                                                 | Unmitigated Consequence                                                                                                                                                                                                                                                                                                                                  | Countermeasure                       |
| :-- | :----------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------- |
| T1  | A tenant has write access to both policies and auth roles simultaneously | The tenant writes a policy containing `path "*"` and assigns it to itself, obtaining full Bastion Vault privileges, including intermediate CA issuance and transit key decryption                                                                                                                                                                        | Section 3 Item E                     |
| T2  | `allowed_parameters` matches policy names via glob patterns              | Strings like `<code>-a,other` are split into two distinct policies by the auth method, allowing the tenant to assign policies outside its cap                                                                                                                                                                                                            | Section 3 Item E.4                   |
| T3  | Tenant secret IDs are issued by Terraform                                | Secret IDs enter state files, outputs, and KV storage, allowing any layer with read access to pgg state to log in as the tenant indefinitely                                                                                                                                                                                                             | Section 3 Item D                     |
| T4  | mp reads pgg state via `terraform_remote_state`                          | The reader acquires the entire state snapshot. If the GitLab token used for reading carries the Maintainer role, the reader could tamper with pgg state to induce unintended actions during the next apply                                                                                                                                               | Section 4 Item C                     |
| T5  | Published facts reside on paths writable by the tenant                   | The tenant tampers with the domains or CIDR blocks constraining itself, causing subsequent layers reading those facts to apply relaxed values                                                                                                                                                                                                            | Section 4 Item C.2                   |
| T6  | Platform trust facts can be overridden by tfvars, `-var`, or `TF_VAR_`   | An uncommitted local value can relax Name Constraints without visibility in the code review process                                                                                                                                                                                                                                                      | Section 4 Item A                     |
| T7  | Intermediate CAs lack Name Constraints                                   | A compromised SPIRE or Downstream Vault CA can issue certificates for `127.0.0.1` or `172.16.0.1` to spoof the Bastion Vault listener. An attacker who also controls the network path, such as DNS or routing, receives the tokens of clients which trust the `pki-root` bundle; clients pinned to `MetaProvisionVaultCA` reject the spoofed certificate | Section 4 Item B                     |
| T8  | Downstream Vault CA is allowed to issue SPIFFE URIs                      | A compromised Downstream Vault can issue arbitrary SVIDs to impersonate any workload identity                                                                                                                                                                                                                                                            | Section 4 Item B.2                   |
| T9  | The transit unseal policy is assignable on shared mounts                 | A leaked tenant token creates a GitLab CI JWT role with overly broad claims and attaches the transit unseal policy, allowing any CI job with network reachability to the Bastion Vault to decrypt the Downstream Vault root key once the CI job also obtains the encrypted root key from the Downstream Vault storage                                    | Section 3 Item E.4                   |
| T10 | The transit key is exportable or allows plaintext backup                 | An attacker obtaining the key and the encrypted root key from the Downstream Vault storage can decrypt the root key offline without leaving any decrypt entries in audit logs                                                                                                                                                                            | Section 4 Item D                     |
| T11 | The terminal outputs token accessors                                     | An accessor captured in scrollback can be used by an identity holding `lookup-accessor` or `revoke-accessor` privileges to inspect or revoke session tokens                                                                                                                                                                                              | Section 5 Item C                     |
| T12 | Audit devices are disabled or modified without detection                 | Operations executed by an attacker after disabling audit logging leave no traces, making post-incident investigation impossible                                                                                                                                                                                                                          | Section 5                            |
| T13 | A wrapping token is intercepted in transit                               | The interceptor unwraps the token first to obtain the secret ID and log in. If the legitimate workflow proceeds without verifying unwrap responses, interception remains undetected                                                                                                                                                                      | Section 3 Item D.3                   |
| T14 | The root token or ambient `VAULT_TOKEN` is sent with requests            | The root token appears in unwrap or login calls, or leaks into the sub-shell, effectively elevating the tenant session to a root session                                                                                                                                                                                                                 | Section 3 Item D.3, Section 6 Item C |
| T15 | Tokens are not revoked when sessions terminate                           | When `./governance` is interrupted by Ctrl-C or context cancellation, the tenant token remains valid within its TTL and can be acquired by other processes on the same host                                                                                                                                                                              | Section 3 Item D.3, Section 6 Item C |

### Item D. Existing Constraints

1.  Vault OSS does not provide Sentinel, namespaces, or audit filters.
2.  Vault OSS does not enforce content restrictions on policies, nor does it restrict which policies can be assigned by auth roles.
3.  An identity capable of writing both policies and auth roles can craft a policy containing `path "*"` and assign it to itself, obtaining arbitrary privileges.
4.  When `allowed_parameters` in ACLs matches via glob patterns, strings containing commas such as `<code>-a,other` are accepted and subsequently split into two separate policies by the auth method.
5.  `terraform_remote_state` downloads the complete state snapshot, giving readers access to all resource attributes; `sensitive = true` only masks values in CLI output.
6.  Reading Terraform state from GitLab requires the Developer role, while writing and locking state requires the Maintainer role.
7.  Destroying a `vault_kv_secret_v2` resource with the default `delete_all_versions = false` soft deletes only the latest version. Earlier versions stay readable, and the latest version stays recoverable until the versions are destroyed or the metadata is deleted.
8.  Vault provider 5.5.0 deprecated the data source `vault_kv_secret_v2`.

### Item E. Design Principles

1.  Every privilege MUST be held by the lowest identity in the hierarchy.
2.  Every Vault path MUST have only one writer.
3.  Every authorization boundary value MUST have a single declaration source, and that source MUST undergo version control and review.
4.  Secrets MUST NOT enter any Terraform state, KV copy, or output.
5.  Any check failure MUST abort the entire workflow; partial results cannot be applied.
6.  Daily operations MUST NOT require manual credential delivery.

## Section 3. Identity and Permission Hierarchy

### Item A. Hierarchy Overview

Identities on the Bastion Vault are structured into five tiers. Each tier receives its policies from the tier above, and a tier cannot obtain a policy which the tier above has neither declared nor placed within the assignable cap.

| Tier | Identity                 | Acquisition Method                                    | Privilege Scope                                                      | Location                                             |
| :--- | :----------------------- | :---------------------------------------------------- | :------------------------------------------------------------------- | :--------------------------------------------------- |
| L0   | root token               | Vault initialization                                  | Complete privileges on Bastion Vault                                 | `~/.vault-token` on the operator workstation         |
| L1   | pgg Terraform            | Executed using the root token                         | Declaring mounts, policies, roles, PKI, and registry                 | The Terraform process of pgg                         |
| L2   | tenant token             | Logged in via tenant session using the tenant AppRole | Tenant ACL and `registry-reader-<code>`                              | Environment variable of the tenant session sub-shell |
| L3   | Component operator token | Logged in by mp using a SPIRE JWT-SVID                | Requested policies written by the broker                             | The Terraform process of mp                          |
| L4   | Workload token           | Logged in via Kubernetes auth, AppRole, or JWT        | Single-purpose policies, such as transit unseal or sign-intermediate | Workload processes                                   |

### Item B. L0 root token

1.  The root token MUST only be used on the operator workstation.
2.  The known consumers of the root token are pgg Terraform, the `./governance` Vault lifecycle commands, the `./governance` steps issuing tenant sessions, and operator scripts which read `~/.vault-token`, such as `build-governance.sh` and the commands in `note.md`.
3.  `./governance` MUST NOT pass the root token into the tenant session sub-shell.
4.  Every use of the root token triggers a `vault-audit-alert`, which serves as an expected operational signal.

### Item C. L1 pgg Terraform

1.  The Terraform runs for pgg are executed on the operator workstation using the root token.
2.  `foundation-vault-bastion` declares auth mounts, PKI mounts, transit mounts, registry mounts, audit devices, tenant AppRoles, and policies held by pgg.
3.  `group-vault-policy-broker` declares tenant ACLs and policies requested by tenants.
4.  State files for both layers are stored in GitLab project `86417732`; the state MUST NOT contain any secrets, as verified in Section 9 Step E.
5.  Applies MUST use a saved plan: executing `terraform plan -out=tfplan` first, followed by `terraform apply tfplan` after review.

### Item D. L2 Tenant AppRole and tenant session

This section addresses T3, T13, T14, and T15 from Section 2 Item C. The tenant AppRole serves as the sole entry point for tenants before SPIRE is deployed. If credentials for this entry point were long-lived, anyone obtaining them could operate on the Bastion Vault under the identity of that tenant indefinitely.

#### Item D.1 Declaration of Tenant AppRole

`foundation-vault-bastion/resources-tenants.tf` declares one AppRole role for each tenant defined in the tenant registry `local.tenants`.

| Attribute               | Value                                                 | Rationale                                                                                                                                                                                             |
| :---------------------- | :---------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `role_name`             | `<code>-terraform-operator`                           | Tenant ACLs partition authorization scope using name prefixes.                                                                                                                                        |
| `token_policies`        | `<code>-terraform-operator`, `registry-reader-<code>` | The former is the tenant ACL written by the broker; the latter is the read-only registry policy held by pgg.                                                                                          |
| `token_ttl`             | 3600s                                                 | Default validity window for a single session.                                                                                                                                                         |
| `token_max_ttl`         | 14400s                                                | Upper bound for a single session; exceeding this requires opening a new session.                                                                                                                      |
| `token_bound_cidrs`     | `127.0.0.1/32`, `172.16.0.1/32`                       | Requests originating on the operator workstation carry source address `127.0.0.1` or `172.16.0.1`; a token presented from any other source address, such as a VM on the publish network, is rejected. |
| `secret_id_bound_cidrs` | `127.0.0.1/32`, `172.16.0.1/32`                       | A secret ID presented from any other source address is rejected at login.                                                                                                                             |
| `secret_id_num_uses`    | 1                                                     | Each secret ID can only be used for login once.                                                                                                                                                       |
| `secret_id_ttl`         | 60s                                                   | An unused secret ID expires after 60 seconds.                                                                                                                                                         |

Terraform MUST NOT declare `vault_approle_auth_backend_role_secret_id`. Terraform also MUST NOT write the secret ID into KV or outputs.

#### Item D.2 Workflow of tenant session

A tenant session is initiated via `./governance vault tenant-session <code>` or by selecting the menu option `[Vault] Open Tenant Operator Session`. The workflow proceeds through the following steps:

1.  `./governance` initializes an admin client using `~/.vault-token`.
2.  The admin client reads `auth/approle/role/<code>-terraform-operator/role-id`.
3.  The admin client requests a secret ID using response wrapping with `num_uses = 1` and `ttl = 60s`; the response returns only a wrapping token.
4.  A token-free client invokes `sys/wrapping/unwrap` using the wrapping token to retrieve the secret ID.
5.  The token-free client calls `auth/approle/login` with the role ID and secret ID to acquire the tenant token.
6.  `./governance` builds the environment of the child shell, in which the tenant token replaces `VAULT_TOKEN` and `VAULT_ADDR` and `VAULT_CACERT` point to the Bastion Vault, and launches `$SHELL` with that environment.
7.  When the sub-shell exits, `./governance` invokes `auth/token/revoke-self` using the tenant token.

#### Item D.3 Token Boundary Guarantees

1.  The root token MUST only appear in requests for Step 2 and Step 3.
2.  The wrapping token MUST only appear in requests for Step 4.
3.  Requests for Step 5 MUST NOT carry any token, including ambient `VAULT_TOKEN` from the environment.
4.  When unwrap returns HTTP 400, the wrapping token has already been consumed by another party or has expired; `./governance` MUST report `ErrWrapConsumed` and halt, and cannot send a login request.
5.  The revoke after the sub-shell exits MUST execute, even if the sub-shell terminates with a non-zero exit status or the context is canceled.
6.  `./governance` MUST NOT output the token accessor, as justified in Section 5 Item C.

#### Item D.4 Usage Conditions

1.  A tenant session is required only before the SPIRE Parent is operational.
2.  The mp layers requiring a tenant session are `platform-spire-parent` and `provision-spire-parent`. `foundation-libvirt-resources` joins the list once the layer reads `registry`, as listed in Section 10 Item B.
3.  After the SPIRE Parent is established, subsequent mp layers authenticate using SPIRE JWT-SVIDs and do not operate through pgg.
4.  Rebooting the Bastion Vault requires only `./governance vault unseal`; reissuing credentials is not necessary.

### Item E. L2 Tenant ACL and Broker

This section addresses T1, T2, and T9 from Section 2 Item C. Vault OSS does not provide mechanisms to restrict policy contents; authorization boundaries must therefore be enforced by the entity writing the policies.

#### Item E.1 Request Format

1.  Tenants MUST NOT write any ACL policies directly on the Bastion Vault.
2.  Tenants submit requested policies formatted as policy requests stored at `secret/<code>/vault-policy-requests`.
3.  A single revision of a request contains all policies for that tenant. Each key represents a policy name, and its value is a JSON string formatted as `{ "path": {...}, "assignable_policies": [...] }`.
4.  `foundation-vault-bastion` pre-creates an empty request so that the broker can always read the request successfully.
5.  The broker reads the request using data source `vault_generic_secret` pointing to path `secret/<code>/vault-policy-requests`.

#### Item E.2 Validation Rules

If the broker detects any violation, the precondition on `terraform_data.request_validation` causes the entire plan to fail.

| Rule               | Description                                                                                                           |
| :----------------- | :-------------------------------------------------------------------------------------------------------------------- |
| Name               | The name MUST start with `<code>-` and MUST NOT be `<code>-terraform-operator`.                                       |
| Document Structure | The document MUST contain only `path` and `assignable_policies`.                                                      |
| Rule Keys          | Each rule MUST contain only `capabilities`; including keys such as `allowed_parameters` constitutes a violation.      |
| Path Scope         | Paths MUST fall within the tenant scope; capabilities MUST NOT exceed the scope item capabilities, except for `deny`. |
| Request Protection | A rule MUST NOT cover the request itself; glob paths are evaluated by literal prefix.                                 |
| Assignable Scope   | `assignable_policies` MUST be a subset of the tenant cap.                                                             |

#### Item E.3 Tenant ACL Contents

The tenant ACL is generated by the broker under the name `<code>-terraform-operator` and comprises five categories of rules:

| Category     | Path                                                                                                                                                               | Capabilities                                                    |
| :----------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------- |
| kv           | `secret/data/<code>/*`, `secret/metadata/<code>/*`, `secret/delete/<code>/*`, `secret/destroy/<code>/*`, `sys/internal/ui/mounts/secret/*`                         | Data read/write, metadata management, version destruction       |
| auth mount   | `sys/auth`, `sys/auth/<code>-*`, `sys/mounts/auth/<code>-*`, `auth/<code>-*`                                                                                       | Creating and configuring tenant-owned auth mounts               |
| auth role    | `auth/approle/role/<code>-*`, `auth/gitlab-saas-ci-job-jwt-provider/role/<code>-*`                                                                                 | Managing tenant roles on shared mounts                          |
| pki          | `sys/mounts/pki-intermediate`, `pki-intermediate/roles/<code>-*`, `pki-intermediate/issue/<code>-*`                                                                | Managing tenant leaf certificate roles and issuing certificates |
| cross tenant | `secret/data/parent-group-governance/terraform/state-backend`, `secret/data/parent-group-governance/github/publication`, `pki-intermediate/root/sign-intermediate` | Registered item by item, each with explicit justification       |

#### Item E.4 Cap and Scopes

1.  The tenant cap consists of `default`, all policies written by the broker for that tenant, the transit unseal policy owned by that tenant, and `registry-reader-<code>`.
2.  All rules writing to auth roles MUST use `allowed_parameters` to restrict `token_policies` and `policies` to exact policy names, and cannot use globs.
3.  The cap is partitioned into owned and shared scopes based on the auth mount path, as defined in the table below.
4.  Transit unseal policies are assignable only within the owned scope, which contains the tenant-owned Kubernetes auth mounts used by Downstream Vault pods.
5.  Within requested policies, any rule starting with `auth/` containing create, update, or patch actions injects only `default` combined with the `assignable_policies` of that policy, intersected with the cap of that path's scope.
6.  Consequently, an operator of one component cannot assign policies belonging to another component, nor can it assign transit unseal policies via shared mounts.

| Scope  | Applicable Paths                                                                      | Assignable Policies                      |
| :----- | :------------------------------------------------------------------------------------ | :--------------------------------------- |
| owned  | `auth/<code>-*`, i.e., tenant-owned auth mounts                                       | Full cap                                 |
| shared | `auth/approle/role/<code>-*` and `auth/gitlab-saas-ci-job-jwt-provider/role/<code>-*` | Full cap excluding transit unseal policy |

### Item F. L3 Component Operator

1.  A component operator is the Terraform identity for each component in mp, logging in using a SPIRE JWT-SVID after the SPIRE Parent is operational.
2.  The JWT role of the component operator resides in a tenant-owned auth mount and is configured by the tenant within a tenant session, governed by the cap of the owned scope.
3.  The policy of the component operator is requested by the tenant and created by the broker after validation.
4.  The role of the component operator can only assign policies declared in `assignable_policies` of that request.
5.  The component operator MAY hold `registry-reader-<code>` to read published facts from the registry.

### Item G. L4 Workload

Workload identities are declared by mp; permissions on the Bastion side originate from policies within the tenant cap.

| Workload                         | Authentication Method              | Permissions                                | Bindings                                                                                     |
| :------------------------------- | :--------------------------------- | :----------------------------------------- | :------------------------------------------------------------------------------------------- |
| SPIRE Parent upstream authority  | AppRole                            | `sign-intermediate` on the intermediate CA | Secret ID and token bound to the address of the SPIRE Parent node on `vault-bastion-publish` |
| Transit seal of Downstream Vault | Tenant-owned Kubernetes auth mount | `transit-unseal-<consumer>`                | `vault` ServiceAccount in the `vault` namespace, dedicated audience, `token_bound_cidrs`     |
| cert-manager of Downstream Vault | Tenant-owned Kubernetes auth mount | `pki-intermediate/sign/<role>`             | PKI role of the Vault listener                                                               |
| Vault Agent of HAProxy           | Tenant-owned auth mount            | `pki-intermediate/issue/<role>`            | PKI role of the stats listener                                                               |

The roadmap for signing SPIRE Parent and Downstream Vault using constrained intermediate CAs is described in Section 10 Item B.

### Item H. Policies Held by pgg

pgg directly declares two categories of policies which do not carry tenant prefixes. Neither the tenant ACL nor any broker-written policy grants a write on `sys/policies/acl`, and the broker rejects any requested policy name outside the `<code>-` prefix; tenants therefore cannot rewrite these policies.

| Policy                      | Allowed Paths                                                                                          | Holder                                        |
| :-------------------------- | :----------------------------------------------------------------------------------------------------- | :-------------------------------------------- |
| `transit-unseal-<consumer>` | Updates on `transit-unseal/encrypt/<key>`, `transit-unseal/decrypt/<key>`, and `auth/token/renew-self` | Auto-unsealing Vault clusters                 |
| `registry-reader-<code>`    | Reads on `registry/data/<code>/*`, `registry/data/platform/*`, and `sys/internal/ui/mounts/registry`   | Tenant AppRole and tenant component operators |

## Section 4. Root of Trust and Fact Publication

### Item A. Platform Trust Facts

This section addresses T6 from Section 2 Item C. Platform trust facts govern the permitted and excluded scopes of Name Constraints. Any unreviewed modification is equivalent to relaxing certificate trust boundaries.

`foundation-vault-bastion/locals-platform-trust.tf` is the single source of truth for platform trust facts.

| Field                          | Value                                             | Purpose                                                                 |
| :----------------------------- | :------------------------------------------------ | :---------------------------------------------------------------------- |
| `domain_suffix`                | `homelab-infra.dev`                               | Platform domain, permitted DNS scope for `pki-downstream`               |
| `stages`                       | `["production"]`                                  | Deriving the SPIRE trust domain, formatted as `<stage>.<domain_suffix>` |
| `network_cidr`                 | `172.16.0.0/16`                                   | Platform network CIDR, permitted IP scope for `pki-downstream`          |
| `bastion_publish_cidr`         | `172.16.0.0/24`                                   | Bastion publish network CIDR, excluded IP scope for `pki-downstream`    |
| `downstream_extra_dns_domains` | `hubble-grpc.cilium.io`, `hubble-relay.cilium.io` | Cilium names Hubble mTLS peers using fixed suffixes                     |

1.  Platform trust facts MUST be declared as locals.
2.  tfvars, `-var`, and `TF_VAR_` MUST NOT be able to override platform trust facts.
3.  `check "platform_trust_consistent"` asserts that `stages` is non-empty and that `bastion_publish_cidr` resides within `network_cidr`. A failed assertion of a `check` block produces a warning and does not stop the plan or the apply (refer to the [Terraform check block documentation](https://developer.hashicorp.com/terraform/language/block/check)); the gap is listed in Section 10 Item A.

### Item B. Intermediate CAs Restricted by Name Constraints

This section addresses T7 and T8 from Section 2 Item C. The trust bundles of both the workstation and platform nodes trust `pki-root`, accepting any certificate which chains back to `pki-root`. When an intermediate CA lacks Name Constraints, the blast radius of a compromised subordinate CA extends to the entire trust domain of `pki-root`.

#### Item B.1 PKI Hierarchy

| Mount              | Issuer      | Purpose                                                                                                         | `max_path_length` |
| :----------------- | :---------- | :-------------------------------------------------------------------------------------------------------------- | :---------------- |
| `pki-root`         | Self-signed | Infrastructure Root CA, `prevent_destroy`                                                                       | Unlimited         |
| `pki-intermediate` | `pki-root`  | Bootstrap Issuing Intermediate, signs leaf certificates prior to SPIRE establishment                            | Unlimited         |
| `pki-spire`        | `pki-root`  | Target issuer of the SPIRE Parent CA, which in turn signs the SPIRE Child CA; migration in Section 10 Item B    | 2                 |
| `pki-downstream`   | `pki-root`  | Target issuer of the Downstream Vault CA, which in turn signs one mesh CA layer; migration in Section 10 Item B | 2                 |

pgg embeds the Name Constraints of `pki-spire` and `pki-downstream` into the intermediate CA certificates through `root/sign-intermediate` on `pki-root`. Subordinate callers cannot omit or loosen these restrictions.

#### Item B.2 Constraint Details

| Mount            | Permitted                                                 | Excluded                                                                |
| :--------------- | :-------------------------------------------------------- | :---------------------------------------------------------------------- |
| `pki-spire`      | DNS and URI: SPIRE trust domain                           | All IPv4 and IPv6                                                       |
| `pki-downstream` | DNS: `domain_suffix` and Hubble names; IP: `network_cidr` | IP: `bastion_publish_cidr`; URI: `domain_suffix` and `.<domain_suffix>` |

1.  `pki-spire` excludes all IP addresses, preventing certificates issued by SPIRE from spoofing Bastion addresses `127.0.0.1` or `172.16.0.1`.
2.  `pki-downstream` excludes URIs under the platform domain and every subdomain of the platform domain, a range which contains the SPIFFE trust domain, preventing the Downstream Vault from issuing SVIDs.
3.  `pki-downstream` excludes the Bastion publish CIDR, ensuring that a compromised Downstream Vault cannot issue listener certificates for the Bastion Vault.

#### Item B.3 SAN Requirements for Subordinate CAs

1.  When the issuing CA carries Name Constraints, the certificate issued through `root/sign-intermediate` MUST carry at least one SAN.
2.  A CSR lacking a SAN is rejected by Vault with the error: `issuer has name constraints but leaf doesn't have a SAN extension`.
3.  With `use_csr_values = false`, Vault takes the SANs from the `alt_names`, `ip_sans`, and `uri_sans` request parameters instead of the CSR. Whether the SPIRE Vault upstream authority plugin supplies `uri_sans` MUST be verified during the SPIRE Parent migration.
4.  The intermediate CA of the Downstream Vault MUST include DNS names within the permitted scope in `alt_names`, and cannot rely solely on `exclude_cn_from_sans`.

### Item C. Registry

This section addresses T4 and T5 from Section 2 Item C. The choice of publication channel simultaneously dictates what data readers can view and whether readers can modify the values they consume.

#### Item C.1 Publication Contents

`foundation-vault-bastion/registry.tf` declares the KV v2 mount `registry` along with two types of publications. Each field of `registry/<code>/bastion` holds one JSON object. In `registry/platform/trust`, `spire_trust_domains` holds a JSON array, and the remaining fields hold plain strings.

| Path                      | Field                                                                          | Contents                                                                                                        |
| :------------------------ | :----------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------- |
| `registry/platform/trust` | `domain_suffix`, `spire_trust_domains`, `network_cidr`, `bastion_publish_cidr` | Platform trust facts from Item A                                                                                |
| `registry/<code>/bastion` | `vault`                                                                        | Bastion endpoint and listener CA PEM                                                                            |
| `registry/<code>/bastion` | `pki`                                                                          | Root and bootstrap intermediate CA PEMs, `pki-intermediate` path, and tenant-owned constrained intermediate CAs |
| `registry/<code>/bastion` | `transit_unseal`                                                               | Transit mount path, and the key and policy names owned by the tenant                                            |
| `registry/<code>/bastion` | `policy_request`                                                               | Mount and name of the request                                                                                   |

#### Item C.2 Access Rules

1.  Only `foundation-vault-bastion` of pgg MAY write to `registry`.
2.  The publication path MUST NOT fall under tenant-writable `secret/<code>/`; allowing tenants to write to publication locations would let them loosen the facts which constrain them.
3.  Tenants consume publication content using `registry-reader-<code>`.
4.  Consumers read data via data source `vault_generic_secret`, decode JSON fields with `nonsensitive(jsondecode(...))`, and read plain string fields with `nonsensitive(...)`.
5.  Consumers MUST inspect the read fields using preconditions.
6.  The registry is not permitted to publish secret IDs, role IDs, or any private keys.

### Item D. Transit Unseal on the Bastion Side

This section addresses T9 and T10 from Section 2 Item C. Decrypt permissions on a transit key, together with the encrypted root key in the Downstream Vault storage, are equivalent to the unseal capability of the Downstream Vault.

1.  `foundation-vault-bastion/transit-unseal.tf` declares the mount `transit-unseal`, isolated from PKI mounts.
2.  Each auto-unsealing Vault cluster maintains a dedicated `aes256-gcm96` key.
3.  Both `exportable` and `allow_plaintext_backup` remain false on keys; once enabled, these cannot be turned off.
4.  `deletion_allowed` remains false on keys.
5.  Policy `transit-unseal-<consumer>` permits only encrypt, decrypt, and `auth/token/renew-self` on that specific key.
6.  The Kubernetes auth role on the consumer side is declared by mp, configured with `token_no_default_policy = true`, `token_period = 3600`, and `token_bound_cidrs`.

## Section 5. Audit and Alerts

This section addresses T11 and T12 from Section 2 Item C. Vault does not raise alerts on audit events; detection relies on periodic evaluation of the audit log.

### Item A. Audit Devices

1.  `foundation-vault-bastion/audit.tf` enables two file-based audit devices.
2.  The `file` device writes to `/opt/vault/audit/audit.log`, mapped to `parent-group-governance/vault/audit` on the host, with mode `0600`.
3.  The `stdout` device passes through container logging into journald.
4.  Vault processes requests as long as either device can accept writes, failing requests only when both devices become unreachable.

### Item B. Detection Rules

`workstation_vault_audit` installs `vault-audit-check.timer` in the systemd user manager of the operator account, executing `vault_audit_check.py` every 5 minutes by default.

1.  Prior to execution, logrotate rotates logs exceeding 100MB and preserves 14 copies.
2.  The script records the inode and read offset of the log file, consuming any remainder in `audit.log.1` after a rotation occurs.
3.  The script inspects only records with `type` equal to `response`.
4.  Every finding is written to the systemd journal via `logger --priority auth.alert --tag vault-audit-alert`.

| Rule                              | Trigger Condition                                                                                                                   |
| :-------------------------------- | :---------------------------------------------------------------------------------------------------------------------------------- |
| Transit key management            | Any path under `transit-unseal/` other than encrypt and decrypt                                                                     |
| Transit failure                   | Requests under `transit-unseal/` carrying an error                                                                                  |
| Transit source                    | Source address of an encrypt or decrypt request not in `workstation_vault_audit_transit_source_cidrs`; skipped if the list is empty |
| Audit modification                | Writes targeting `sys/audit*`                                                                                                       |
| root token                        | `auth.policies` containing `root`                                                                                                   |
| Denied privilege escalation write | Denied writes targeting `sys/policies/acl/` or `role`, `users`, `groups`, `certs` under auth mounts                                 |

### Item C. Accessors and HMAC

1.  The detection rules rely only on `request.path`, `request.operation`, `request.remote_address`, `error`, and `auth.policies`, which the Bastion audit log records in plaintext; Vault hashes most other string values (refer to [Vault audit devices](https://developer.hashicorp.com/vault/docs/audit)).
2.  Token accessors are HMAC-hashed by default according to `hmac_accessor = true` (refer to the [Vault audit API](https://developer.hashicorp.com/vault/api-docs/system/audit)).
3.  The `accessor=` output in alert messages represents an HMAC hash value and must be resolved through `sys/audit-hash` when correlating.
4.  Because an accessor can be used to look up or revoke tokens, `./governance` does not output raw accessors to the terminal.

## Section 6. governance CLI

### Item A. Package Architecture

| Package             | File                     | Responsibility                                                                                                                        |
| :------------------ | :----------------------- | :------------------------------------------------------------------------------------------------------------------------------------ |
| `pkg/vaultclient`   | `client.go`              | `AppRoleAuth` implements the existing `AuthMethod` interface, sharing `submitLogin` with `JWTAuth` to validate login responses        |
| `internal/vaultops` | `vaultops_tenant.go`     | `OpenTenantSession`, `RunTenantSession`, `RevokeTenantSession`, `BuildTenantSessionEnv`, `ListTenantCodes`                            |
| `cmd/governance`    | `tenant_session.go`      | Initializes admin clients, executes `$SHELL`, captures SIGINT via `signal.Notify`, translates shell exit statuses to operational info |
| `cmd/governance`    | `commands.go`, `menu.go` | Cobra subcommand `vault tenant-session <tenant>` and interactive menu options                                                         |

### Item B. Commands and Menus

1.  `./governance vault tenant-session <tenant>` accepts exactly one argument.
2.  The menu entry `[Vault] Open Tenant Operator Session` is placed after Unseal.
3.  The menu uses the root token to list all roles on the AppRole mount ending with `-terraform-operator`, stripping the suffix for operator selection.
4.  Listed tenant codes MUST match `^[a-z0-9]+(-[a-z0-9]+)*$`; non-conforming roles are excluded.

### Item C. Behavioral Guarantees

1.  Invalid tenant codes are rejected prior to issuing any network requests, failing with `ErrInvalidTenant`.
2.  Every client clone operation invokes `ClearToken()` first, because `vaultapi.Clone()` implicitly inherits ambient `VAULT_TOKEN` from the environment.
3.  If issuance responses lack response wrapping, `OpenTenantSession` reports an error and halts immediately.
4.  Revocation uses `context.WithoutCancel`, guaranteeing execution even after context cancellation.
5.  Errors from shell execution and token revocation are combined using `errors.Join`, ensuring revocation failures are not swallowed.
6.  During active sessions, `./governance` captures SIGINT via `signal.Notify` so that Ctrl-C only interrupts commands executing within the sub-shell.
7.  Signals intercepted by `signal.Notify` revert to default dispositions during exec, allowing commands in the sub-shell to be interrupted by Ctrl-C.
8.  If the shell terminates with a non-zero exit status, `./governance` logs the status as INFO and does not treat it as an execution failure.
9.  If the shell fails to launch, `./governance` returns an error.

### Item D. Testing

| File                                                                    | Tests                                                                                               | Coverage                                                                                                                                                        |
| :---------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pkg/vaultclient/client_approle_test.go`                                | `TestAppRoleAuth_*`                                                                                 | Logins on default and custom mounts, input validation, server errors, and missing client tokens                                                                 |
| `internal/vaultops/vaultops_tenant_test.go`                             | `TestOpenTenantSession_*`, `TestRevokeTenantSession_*`, `TestBuildTenantSessionEnv`                 | Token boundaries, single-use wrapping requests, halts upon consumed wrapping, 7 Vault fault responses, tenant code validation, environment variable replacement |
| `internal/vaultops/vaultops_tenant_run_test.go`                         | `TestRunTenantSession_*`                                                                            | Revocation after shell exit, revocation on shell failure or context cancellation, skipping shell launch on open failure, reporting revocation failures          |
| `internal/vaultops/vaultops_tenant_list_test.go`                        | `TestListTenantCodes*`                                                                              | Role filtering and sorting, mounts with no roles, LIST rejection                                                                                                |
| `cmd/governance/tenant_session_test.go`                                 | `TestRunInteractiveShell_*`, `TestRunSessionShell_*`, `TestNewVaultCmd_*`, `TestRunTenantSession_*` | Environment variable propagation, exit status handling, launch failures, argument cardinality, missing root tokens                                              |
| `cmd/governance/menu_test.go`                                           | `TestBuildMenuOptions_*`, `TestRunTenantSessionMenu_*`                                              | Menu sequence, aborting session launch on empty tenant or invalid selection                                                                                     |
| `ansible/roles/workstation_vault_audit/tests/test_vault_audit_check.py` | 20 pytest test cases                                                                                | 6 detection rules, log rotation and truncation, state persistence                                                                                               |

Tests utilize httptest to simulate the Bastion Vault. Mock endpoints mirror Vault behavior: wrapping tokens can only be unwrapped once, and mounts without roles return 404.

## Section 7. Trade-offs in Section 2 Item C

### Item A. Tenant Policies Written by Broker

For risks associated with rejecting this choice, refer to T1 and T2.

1.  Constraint: Vault OSS does not restrict policy content; tenants capable of writing both policies and roles can achieve arbitrary privilege escalation.
2.  Decision: Tenants submit requests only; the broker writes policies after validation, and all role definitions restrict assignable policies to exact names.
3.  Cost: Adding or modifying policies requires executing another apply on the broker layer.
4.  Rejected alternative: Allowing tenants to write policies prefixed with their names. Prefixes do not restrict the policy capabilities within.

### Item B. Tenant Secret ID Delivery Mechanism

For risks associated with rejecting this choice, refer to T3, T13, and T15.

1.  Constraint: If secret IDs are issued by Terraform, they enter pgg state, allowing any layer reading that state to obtain them.
2.  Decision: `./governance` issues a single-use wrapped secret ID per session; tenant tokens exist solely in sub-shell memory.
3.  Cost: Every session opening requires the root token, a single session lasts at most 4 hours, and sessions cannot be established without the operator at the workstation.
4.  Value of response wrapping: If a wrapping token is consumed by an adversary first, unwrap fails, prompting `./governance` to halt and alert, rendering interception detectable.
5.  Rejected alternatives and rationales are summarized in the table below:

| Alternative                                         | Rationale for Rejection                                           |
| :-------------------------------------------------- | :---------------------------------------------------------------- |
| Terraform issues and writes to KV and outputs       | Secret IDs never expire and persist in state files                |
| Dedicating a separate Terraform layer for issuance  | Secret IDs still enter that layer's state file                    |
| Storing unwrapped secret IDs on the host filesystem | Leaves an additional long-lived credential on disk                |
| Retaining secret IDs across sessions                | Secret IDs are single-use; holding the tenant token is sufficient |

### Item C. Fact Publication Channel

For risks associated with rejecting this choice, refer to T4 and T5.

1.  Constraint: `terraform_remote_state` downloads the complete state snapshot; consumers require GitLab tokens with read access to the pgg project, and the Maintainer role confers write access.
2.  Decision: pgg publishes facts to the `registry` mount, and tenants access them read-only via Vault ACLs.
3.  Cost: Consumers must hold a Vault token; KV values are stored as strings, requiring consumers to decode and validate them independently.

| Alternative                                         | Rationale for Rejection                                                                        |
| :-------------------------------------------------- | :--------------------------------------------------------------------------------------------- |
| Retaining `terraform_remote_state`                  | Consumers acquire complete state snapshots and require GitLab tokens for the pgg project       |
| Reading state with a Developer-role read-only token | Consumers still acquire complete state snapshots                                               |
| Consul KV                                           | Requires deploying stateful services and bootstrapping ACLs, introducing another root of trust |
| SSM Parameter Store                                 | Coupled with AWS, incompatible with on-prem and Nutanix migration                              |
| Publishing to `secret/<code>/`                      | Writable by the tenant, allowing it to relax the constraints placed on itself                  |

Terraform documentation recommends publishing external data outside state files to maintain decoupled access controls (refer to [The terraform_remote_state Data Source](https://developer.hashicorp.com/terraform/language/state/remote-state-data)).

### Item D. Platform Trust Facts Declaration Mechanism

For risks associated with rejecting this choice, refer to T6.

1.  Constraint: `.gitignore` in pgg ignores `*.tfvars`; changes to tfvars do not appear in merge requests.
2.  Decision: Platform trust facts are declared using locals.
3.  Cost: Modifying domains or network CIDR blocks requires code changes and merge request reviews.

| Alternative                    | Rationale for Rejection                                                             |
| :----------------------------- | :---------------------------------------------------------------------------------- |
| tfvars                         | Changes bypass peer review and can relax Name Constraints locally                   |
| `variable` with defaults       | Can be overridden via `-var`, `TF_VAR_`, and `*.auto.tfvars` without leaving a diff |
| Declared by mp and read by pgg | Allows the constrained party to define its own constraints                          |

### Item E. Enforcement Point of Name Constraints

For risks associated with rejecting this choice, refer to T7 and T8.

1.  Constraint: Constraint parameters for `root/sign-intermediate` are supplied by the caller, meaning the caller can omit them.
2.  Decision: pgg declares dedicated constrained intermediate mounts, baking restrictions directly into intermediate CA certificates to cover the entire subordinate tree.
3.  Cost: Introducing a new category of subordinate CA requires pgg to configure an additional mount.

### Item F. Cap Scope Partitioning

For risks associated with rejecting this choice, refer to T9.

1.  Constraint: Tenants can configure arbitrary claims and origins on shared AppRole and GitLab CI JWT roles.
2.  Decision: Transit unseal policies are restricted exclusively to tenant-owned auth mounts.
3.  Cost: `auth/<code>-*` encompasses all auth mount types created by a tenant, meaning paths cannot differentiate between Kubernetes auth and JWT auth.

### Item G. CLI Output and Exit Status

For risks associated with rejecting this choice, refer to T11.

1.  Accessors are omitted from output, as justified in Section 5 Item C.
2.  The sub-shell exit status reflects only the last command executed within the shell, unrelated to whether the session was successful; `./governance` therefore outputs the exit status as INFO.

## Section 8. Deployment Order

### Step A. Greenfield Deployment

1.  Generate the Bastion Vault TLS material with `./governance vault tls-generate`.
2.  Start the Bastion Vault container from `compose.yml`, which declares the audit volume.
3.  Initialize the Bastion Vault, unseal the Bastion Vault, and enable the KV v2 engine through `./governance`.
4.  Apply `foundation-vault-bastion`.
5.  Apply `group-vault-policy-broker`. At this stage, policy requests are empty; the broker writes only tenant ACLs.
6.  Execute the `workstation_vault_audit` playbook, passing `workstation_vault_audit_home`.
7.  Launch a tenant session to execute Phase 1 layers of mp, following the sequence documented in `architecture_meta-platform_deployment-chain.md` in the planning repository.
8.  Once mp populates policy requests, apply `group-vault-policy-broker` once more.

### Step B. Routine Operations

1.  Execute `./governance vault unseal` after any Bastion Vault reboot.
2.  Open a tenant session whenever tenant operations on the Bastion Vault are required, exiting the sub-shell upon completion.
3.  Generate plans for Terraform changes using `terraform plan -out=tfplan`, reviewing them before executing `terraform apply tfplan`.

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
terraform -chdir=terraform/layers/group-vault-policy-broker validate
```

`./build-governance.sh` executes Go tests, Python tests, SonarQube scanning, and CLI compilation in order.

### Step B. Tenant Session Verification

Execute the following commands within the tenant session sub-shell:

```bash
echo "VAULT_TOKEN ${VAULT_TOKEN:+set}"
[ "$VAULT_TOKEN" != "$(cat ~/.vault-token)" ] && echo "tenant token, not the root token"
vault token lookup -format=json | jq '{path: .data.path, policies: .data.policies, ttl: .data.ttl, bound_cidrs: .data.bound_cidrs}'
vault policy list
ps -o comm= -p "$(ps -o ppid= -p $$)"
exit
```

| Command              | Expected Result                                                                                                                                                                           |
| :------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Token check          | `VAULT_TOKEN set`, and token differs from the root token                                                                                                                                  |
| `vault token lookup` | `path` is `auth/approle/login`, policies are `default`, `<code>-terraform-operator`, `registry-reader-<code>`, `ttl` does not exceed 3600, `bound_cidrs` are `127.0.0.1` and `172.16.0.1` |
| `vault policy list`  | 403 permission denied                                                                                                                                                                     |
| Parent process       | `governance`                                                                                                                                                                              |
| `exit`               | `Tenant session token revoked.`                                                                                                                                                           |

### Step C. Registry and Privilege Boundary Verification

Execute the following commands within the tenant session sub-shell:

```bash
vault kv get -format=json registry/meta-platform/bastion | jq '.data.data | keys'
vault kv get -field=spire_trust_domains registry/platform/trust
vault kv put registry/meta-platform/bastion x=y
vault write auth/approle/role/meta-platform-scope-test token_policies=transit-unseal-meta-platform-vault-downstream
vault kv metadata get secret/meta-platform/terraform/approle
```

| Command                                              | Expected Result                                                           |
| :--------------------------------------------------- | :------------------------------------------------------------------------ |
| Read `registry/meta-platform/bastion`                | Fields are `pki`, `policy_request`, `transit_unseal`, `vault`             |
| Read `registry/platform/trust`                       | `["production.homelab-infra.dev"]`                                        |
| Write to registry                                    | 403 permission denied                                                     |
| Assign transit unseal policy on shared AppRole mount | 403 permission denied, and triggers a `denied policy or role write` alert |
| Legacy approle KV                                    | `No value found`                                                          |

### Step D. Name Constraints Verification

Verification of Name Constraints comprises two parts. The first verifies that Vault rejects non-compliant names during issuance. The second simulates a compromised intermediate CA private key, using locally signed leaf certificates to confirm that `openssl verify` rejects non-compliant names. The following commands run using the root token; the test CA has a TTL of 1 hour and MUST be revoked after verification concludes.

```bash
export VAULT_ADDR='https://172.16.0.1:8200'
export VAULT_CACERT="$PWD/vault/tls/ca.pem"
vault read -field=certificate pki-root/cert/ca > root.pem
vault read -field=certificate pki-spire/cert/ca > inter.pem

openssl req -new -newkey rsa:2048 -nodes -keyout test-ca.key -subj "/CN=nc-test.production.homelab-infra.dev" -out test-ca.csr
vault write -format=json pki-spire/root/sign-intermediate csr=@test-ca.csr \
  common_name=nc-test.production.homelab-infra.dev exclude_cn_from_sans=true \
  uri_sans=spiffe://production.homelab-infra.dev/nc-test ttl=1h > test-ca.json
jq -r .data.certificate test-ca.json > test-ca.pem

openssl req -new -newkey rsa:2048 -nodes -keyout leaf.key -subj "/CN=nc-leaf" -out leaf.csr
printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=IP:172.16.0.1\n' > leaf.ext
openssl x509 -req -in leaf.csr -CA test-ca.pem -CAkey test-ca.key -CAcreateserial -days 1 -extfile leaf.ext -out leaf.pem
cat test-ca.pem inter.pem > chain.pem
openssl verify -CAfile root.pem -untrusted chain.pem leaf.pem

vault write pki-spire/revoke serial_number="$(jq -r .data.serial_number test-ca.json)"
```

The expected output of `openssl verify` for non-compliant names is `excluded subtree violation` or `permitted subtree violation`. Swapping `subjectAltName` with names from the table below allows testing additional scenarios:

| Mount            | Expected Pass                                                                                        | Expected Rejection                                                                                                        |
| :--------------- | :--------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------ |
| `pki-spire`      | `URI:spiffe://production.homelab-infra.dev/ns/a/sa/b`                                                | `URI:spiffe://evil.example/ns/a`, `IP:172.16.0.1`, `IP:127.0.0.1`, `DNS:localhost`                                        |
| `pki-downstream` | `DNS:keycloak.production.homelab-infra.dev,IP:172.16.130.250`, `DNS:a.default.hubble-grpc.cilium.io` | `IP:172.16.0.1`, `IP:127.0.0.1`, `DNS:localhost`, `DNS:gitlab.com`, `URI:spiffe://production.homelab-infra.dev/ns/a/sa/b` |

The test CA for `pki-downstream` does not have a URI SAN; the request MUST supply `alt_names=nc-test.homelab-infra.dev` instead. Experimental results recorded on 2026-10-03 are as follows:

| Item                                                             | Result                                                                                                            |
| :--------------------------------------------------------------- | :---------------------------------------------------------------------------------------------------------------- |
| Vault rejects non-compliant names during issuance                | `pki-spire` Bastion IP and external DNS; `pki-downstream` `localhost`, Bastion IP, and SVID: all 5 items rejected |
| Subordinate self-signed leaf certificates under `pki-spire`      | 1 expected pass succeeded, 4 expected rejections were all rejected                                                |
| Subordinate self-signed leaf certificates under `pki-downstream` | 2 expected passes succeeded, 5 expected rejections were all rejected                                              |
| Path length                                                      | Test CA `pathlen` decrements from 2 to 1; scenarios exceeding path limits remain untested                         |

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

In the expected output, only `data_json` of `registry_platform_trust` and `registry_tenant_bastion` contains data, representing the public facts detailed in Section 4 Item C. `data` and `data_json` for `tenant_policy_request` MUST equal `{}`, and all other sensitive attributes MUST be `null`.

### Step F. Alerts

```bash
journalctl --user -t vault-audit-alert --since today
systemctl --user list-timers vault-audit-check.timer
```

Root token usage and rejected role writes MUST appear in the systemd journal.

## Section 10. Residual Risks and Next Steps

### Item A. Residual Risks

1.  The root token resides in `~/.vault-token` on the operator workstation; if the workstation is compromised, the Bastion Vault is compromised.
2.  Audit logs lack a remote sink; if the host is compromised, audit logs can be tampered with.
3.  Alerts are written only to journald without push notification channels, and the user timer requires systemd linger when the operator is not logged in.
4.  The owned scope of `auth/<code>-*` covers JWT auth mounts created by the tenant.
5.  `pki-intermediate` lacks Name Constraints and `max_path_length`; an identity holding `sign-intermediate` privileges on it can issue unconstrained intermediate CAs.
6.  `meta-gitlab-project` in mp still reads state from other pgg layers; mp therefore still requires a GitLab token with read privileges on the pgg project.
7.  Ansible defaults in `workstation_libvirt` independently declare `172.16.0.1`, representing a secondary declaration source for the Bastion publish address.
8.  `check "platform_trust_consistent"` only warns on a failed assertion, which falls short of principle 5 in Section 2 Item E.

### Item B. Next Steps

1.  Migrate 16 layers of mp to read from `registry`, removing `terraform_remote_state` references targeting `foundation-vault-bastion`.
2.  Transition SPIRE Parent issuance to `pki-spire` and Downstream Vault issuance to `pki-downstream`, populating DNS SANs in the Downstream Vault CSR.
3.  Configure `max_path_length = 0` on `pki-intermediate`, removing cross-tenant authorization for `pki-intermediate/root/sign-intermediate`.
4.  Deprecate the broker layer in favor of direct component role and policy declarations by pgg.
5.  Integrate the secret scanning routine from Step E into pgg CI pipelines.
6.  Conduct verification testing for path length limit rejections when exceeding allowed CA tiers.
7.  Consolidate declaration sources for the Bastion publish address.
8.  Replace `check "platform_trust_consistent"` with a precondition which stops the plan on a failed assertion.
