# Parent Group Governance Lexicon

This document records the naming conventions which are specific to the Terraform layers, the Terraform modules, the Ansible roles, and the Go governance tool of `parent-group-governance`.

## Section 1. Scope and Precedence

1. The organization naming standard `planning/architecture-naming-standard.md` governs every naming axis which the organization naming standard defines.
2. This document MUST NOT redefine a rule of the organization naming standard.
3. A conflict between this document and the organization naming standard MUST be resolved in favor of the organization naming standard.
4. This document MUST name only identifiers which exist in the code.
5. The downstream repository `platform-foundation` consumes the Bastion Vault instance, the registry facts, and the GitLab topology declared here. A downstream repository MUST NOT redeclare any of these assets.

The following rules of the organization naming standard apply directly in this repository:

| Naming axis         | Rule                                                                                                                                       | Source in the organization naming standard |
| :------------------ | :----------------------------------------------------------------------------------------------------------------------------------------- | :----------------------------------------- |
| Any name            | A name MUST NOT carry a qualifier which the namespace already implies.                                                                     | Section 3 Item A                           |
| Shared namespace    | A name in a shared namespace MUST carry the owner code qualifier.                                                                          | Section 3 Item A                           |
| Vault instance noun | The Vault instance nouns are `bastion` and `downstream`. The noun `production` MUST name the stage only.                                   | Section 4 Item B and Item C                |
| Terraform output    | An output name MUST follow the form `<subject>_<attribute>`. A new output MUST NOT repeat the subject which the layer name already states. | Section 5 Item D                           |
| Subcommand verbs    | A CLI subcommand MUST use verb-initial ordering.                                                                                           | Section 3 Item C                           |

## Section 2. Vault Instances and Core Nouns

1. The Vault instance nouns across the organization are `bastion` and `downstream`.
2. The noun `bastion` MUST designate the root Bastion Vault instance hosted on the developer workstation.
3. The noun `downstream` MUST designate the platform service Vault instance managed by `platform-foundation`.
4. The terms `bootstrap`, `bootstrapper`, and `shared-vault` MUST NOT serve as Vault instance nouns.
5. The term `production` MUST designate the deployment environment stage alone.

## Section 3. Operator Identities and Access Roles

1. An operator identity on the workstation MUST carry the prefix `operator-`, as in `operator-foundation` and `operator-rotation`.
2. A certificate authentication role in the Bastion Vault MUST match the operator identity, for example `operator-foundation`.
3. An operator proxy access category MUST be declared using the Go domain type `AccessRole`.
4. A tenant identifier MUST be an owner code formatted as lowercase alphanumerics delimited by hyphens, matching the repository name of the tenant.
5. A tenant operator AppRole in the Bastion Vault MUST follow the pattern `<owner_code>-terraform-operator`.

## Section 4. Vault Mounts and Service Boundaries

1. The private infrastructure secrets engine MUST reside at the KV-v2 mount `secret/`.
2. The public platform facts registry MUST reside at the KV-v2 mount `registry/`.
3. The root certificate authority MUST reside at the PKI mount `pki-root/`.
4. Intermediate certificate authorities MUST reside under the PKI mount `pki-intermediate/`.
5. The Downstream Vault transit auto-unseal engine MUST reside at the Transit mount `transit-unseal/`.
6. The workstation operator proxy authentication engine MUST reside at the cert mount `operator-cert/`.
7. The GitLab CI job authentication engine MUST reside at the JWT mount `gitlab-saas-ci-job-jwt-provider/`.
8. The tenant automation authentication engine MUST reside at the AppRole mount `approle/`.

## Section 5. Layer Declarations and File Partitioning

1. Terraform resource files within `foundation-vault-bastion` MUST group related declarations under functional prefix namespaces.
2. Declarations governing authentication mounts, operator proxies, tenant AppRoles, and access control policies MUST reside in files prefixed with `access-`.
3. Declarations establishing downstream platform dependencies, including fact publication and transit unseal keys, MUST reside in files prefixed with `service-`.
4. Declarations establishing cryptographic roots of trust and issuing intermediates MUST reside in files prefixed with `trust-`.

## Section 6. Go Architecture and Secret Zero Type Safety

1. Functions in `tools/governance` MUST follow verb-initial naming conventions:
    - `Resolve` MUST denote computing a path, address, or runtime parameter dynamically from ambient host state or configuration values. Static field accessors MUST NOT use `Resolve`.
    - `Build` MUST denote assembling an in-memory configuration or composite data structure from validated inputs.
    - `Generate` MUST denote creating cryptographic material, TLS certificates, or high-entropy random tokens.
    - `Deploy` MUST denote transmitting and validating a secret change against an external target service. Operations performing live secret deployment MUST NOT use the verb `Apply`.
    - `Stage` MUST denote recording a transactional write-ahead entry to an auxiliary Vault field prior to external deployment.
    - `Commit` MUST denote persisting a deployed and verified secret into primary Vault KV-v2 storage.
    - `Reconcile` MUST denote pushing an existing Vault credential outward to synchronize a drifted external service without credential rotation.
    - `Verify` MUST denote inspecting host binary prerequisites or probing credential validity without mutating state.
2. The Go codebase MUST enforce strong typing for domain primitives:
    - Sensitive credentials MUST be encapsulated within domain types that suppress plaintext leakage during string formatting.
    - High-entropy tokens generated through `crypto/rand` MUST be modeled using the dedicated type `RandomToken`, and MUST NOT carry a hex qualifier when encoded in URL-safe base64.
    - Access roles and credential keys MUST use distinct string-derived domain types rather than primitive strings.
