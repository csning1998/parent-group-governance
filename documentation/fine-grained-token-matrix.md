# Fine-Grained Token Matrix

This document defines the GitLab.com fine-grained personal access tokens across group repositories, the corresponding Bastion Vault storage paths, and the permissions granted to each token.

## Section 1. Context and Constraints

1. The current constraint is the GitLab.com Free tier plan of the group, which provides neither project access tokens nor group access tokens.
2. The chosen path provisions one fine-grained personal access token per repository under the owner account. Setting `access` to selected memberships limits each downstream token to its own project.
3. Each token provides `TF_HTTP_PASSWORD` for the Terraform HTTP state backend and supplies authentication for the `gitlab` provider across the layers of the repository.
4. The associated cost is the manual rotation of each token, which attaches to the personal owner account and expires within 365 days.
5. The owner manages tokens through <https://gitlab.com/-/user_settings/personal_access_tokens?state=active&sort=expires_asc>, which lists active tokens ordered by expiration date.
6. Permission names conform to the GitLab fine-grained permission specifications for the [REST API](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_rest/) and [GraphQL API](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_graphql/).

## Section 2. Token Registry

### Item A. Names and Paths

1. A token name MUST follow `terraform-state-backend-<repository name>`, or `terraform-state-backend-<owner code>` for a subgroup token. The token name serves display purposes only, placing the kind before the repository name to match operator Proxy identity conventions.
2. A token description MUST be `Bastion Vault secret/<owner code>/terraform/state-backend` to record the exact path hosting the token.
3. The token MUST reside in the `token` field under `secret/<owner code>/terraform/state-backend`. The `administrator` proxy identity writes to this path.

| Token name                                              | Owner code                      | Project or group ID | Selected memberships                                                  | Reading identities                                                              |
| ------------------------------------------------------- | ------------------------------- | ------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `terraform-state-backend-parent-group-governance`       | `parent-group-governance`       | `86417732`          | Group `csning1998-lab` and project `parent-group-governance`          | `credential-distributor`, `administrator`                                       |
| `terraform-state-backend-platform-foundation`           | `platform-foundation`           | `84608830`          | Project `csning1998-lab/platform-engineering-lab/platform-foundation` | `platform-foundation`, `credential-distributor-platform-foundation`             |
| `terraform-state-backend-on-premise-gitlab-deployment`  | `opgitlab`                      | `82448331`          | Project `on-premise-gitlab-deployment`                                | `credential-distributor-opgitlab`, `consumer-opgitlab`                          |
| `terraform-state-backend-gitlab-ci-with-code-reviewer`  | `gitlab-ci-with-code-reviewer`  | `83083739`          | Project `gitlab-ci-with-code-reviewer`                                | `credential-distributor-gitlab-ci-with-code-reviewer`, `credential-distributor` |
| `terraform-state-backend-generic-agent-criteria-source` | `generic-agent-criteria-source` | `85419450`          | Project `generic-agent-criteria-source`                               | `credential-distributor-generic-agent-criteria-source`                          |
| `terraform-state-backend-platform-observability`        | `platform-observability`        | `87321619`          | Project `platform-observability`                                      | `consumer-platform-observability`                                               |
| `terraform-state-backend-personal`                      | `personal`                      | `137823265`         | Group `csning1998-lab/personal`                                       | `credential-distributor-personal`                                               |
| `terraform-state-backend-terraform-provider-sshclient`  | `terraform-provider-sshclient`  | `86090557`          | Project `terraform-provider-sshclient`                                | `credential-distributor-terraform-provider-sshclient`                           |

The Reading identities column follows `state_backend_path` and `allowed_read_secret_paths` of `workstation-topology.yaml`. The governance identity `credential-distributor` reads the `gitlab-ci-with-code-reviewer` path through `allowed_read_secret_paths`. The `administrator` identity writes every path of the table.

## Section 3. Permission Matrix

The resource selector of GitLab groups permissions in three levels: a tab (Group and project, User, or Global), a category within the tab, and a resource within the category. Items A to C follow the same levels. Column headers indicate owner codes, each cell lists the granted actions, and `-` withholds the resource.

Action codes: `C` Create, `R` Read, `U` Update, `D` Delete, `L` Lock, `P` Protect.

### Item A. Group and Project Tab

| Category         | Resource                  | `parent-group-governance` | `platform-foundation` | `opgitlab` | `gitlab-ci-with-code-reviewer` | `generic-agent-criteria-source` | `platform-observability` | `personal` | `terraform-provider-sshclient` |
| ---------------- | ------------------------- | ------------------------- | --------------------- | ---------- | ------------------------------ | ------------------------------- | ------------------------ | ---------- | ------------------------------ |
| Projects         | Project                   | RU                        | RU                    | RU         | RU                             | RU                              | RU                       | RU         | RU                             |
| CI/CD            | Terraform State           | CRL                       | CRL                   | CRL        | CRL                            | CRL                             | CRL                      | CRL        | CRL                            |
| CI/CD            | Variable                  | CRUD                      | CRUD                  | CRUD       | CRUD                           | CRUD                            | CRUD                     | CRUD       | CRUD                           |
| CI/CD            | Catalog Resource          | -                         | -                     | -          | CD                             | -                               | -                        | -          | -                              |
| CI/CD            | Runner                    | RUD                       | -                     | -          | -                              | -                               | -                        | -          | -                              |
| Repository       | Branch                    | RP                        | P                     | P          | P                              | P                               | P                        | P          | P                              |
| Repository       | Protected Branch          | RU                        | RU                    | RU         | RU                             | RU                              | RU                       | RU         | RU                             |
| Repository       | Push Rule                 | R                         | R                     | R          | R                              | R                               | R                        | R          | R                              |
| System Access    | Job Token Scope Allowlist | CRD                       | -                     | -          | -                              | -                               | -                        | -          | -                              |
| Project Features | Remote Mirror             | CRUD                      | CRUD                  | CRUD       | CRUD                           | CRUD                            | CRUD                     | CRUD       | CRUD                           |
| Project Features | Remote Mirror Public Key  | R                         | R                     | R          | R                              | R                               | R                        | R          | R                              |
| Groups           | Group                     | RU                        | -                     | -          | -                              | -                               | -                        | -          | -                              |
| Project Planning | Label                     | CRUD                      | -                     | -          | -                              | -                               | -                        | -          | -                              |
| Project Planning | Work Item                 | -                         | -                     | -          | -                              | -                               | -                        | CRUD       | -                              |

### Item B. User Tab

| Category      | Resource | `parent-group-governance` | `platform-foundation` | `opgitlab` | `gitlab-ci-with-code-reviewer` | `generic-agent-criteria-source` | `platform-observability` | `personal` | `terraform-provider-sshclient` |
| ------------- | -------- | ------------------------- | --------------------- | ---------- | ------------------------------ | ------------------------------- | ------------------------ | ---------- | ------------------------------ |
| System Access | User     | R                         | R                     | R          | R                              | R                               | R                        | R          | R                              |
| Groups        | Group    | C                         | -                     | -          | -                              | -                               | -                        | -          | -                              |
| CI/CD         | Runner   | C                         | -                     | -          | -                              | -                               | -                        | -          | -                              |
| Projects      | Project  | C                         | -                     | -          | -                              | -                               | -                        | -          | -                              |

### Item C. Global Tab

| Category      | Resource | `parent-group-governance` | `platform-foundation` | `opgitlab` | `gitlab-ci-with-code-reviewer` | `generic-agent-criteria-source` | `platform-observability` | `personal` | `terraform-provider-sshclient` |
| ------------- | -------- | ------------------------- | --------------------- | ---------- | ------------------------------ | ------------------------------- | ------------------------ | ---------- | ------------------------------ |
| System Access | Metadata | R                         | R                     | R          | R                              | R                               | R                        | R          | R                              |

### Item D. Terraform Consumers

| Category         | Resource                  | Actions | Terraform consumer                                                                                                                    |
| ---------------- | ------------------------- | ------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| CI/CD            | Terraform State           | CRL     | The HTTP backend of every layer                                                                                                       |
| CI/CD            | Variable                  | CRUD    | `gitlab_project_variable` of the project, WIF, and code reviewer modules, and `gitlab_group_variable` of `group-gitlab-configuration` |
| CI/CD            | Runner                    | C       | `gitlab_user_runner` of `group-gitlab-runner` through `POST /user/runners`                                                            |
| CI/CD            | Runner                    | RUD     | `gitlab_user_runner` through `GET`, `PUT`, and `DELETE /runners/:id`                                                                  |
| CI/CD            | Catalog Resource          | CD      | `gitlab_project_cicd_catalog` through the GraphQL API                                                                                 |
| Projects         | Project                   | C       | The first apply or a rebuild of a downstream project through `POST /projects`                                                         |
| Projects         | Project                   | RU      | `gitlab_project`, `data.gitlab_project`, and the catalog status read of `gitlab_project_cicd_catalog`                                 |
| Repository       | Branch                    | P       | `gitlab_branch_protection`                                                                                                            |
| Repository       | Branch                    | R       | `gitlab_project` creation (Section 5)                                                                                                 |
| Repository       | Protected Branch          | RU      | `gitlab_branch_protection`                                                                                                            |
| Repository       | Push Rule                 | R       | `gitlab_project` and `gitlab_group` refresh (Section 5)                                                                               |
| System Access    | Job Token Scope Allowlist | CRD     | `gitlab_project_job_token_scope`                                                                                                      |
| System Access    | User                      | R       | The configuration check of the `gitlab` provider (Section 5)                                                                          |
| System Access    | Metadata                  | R       | `gitlab_branch_protection` and `gitlab_group` (Section 5)                                                                             |
| Project Features | Remote Mirror Public Key  | R       | `data.gitlab_project_mirror_public_key`                                                                                               |
| Project Features | Remote Mirror             | CRUD    | `gitlab_project_push_mirror`                                                                                                          |
| Groups           | Group                     | C       | Subgroups of `group-topology` through `POST /groups`                                                                                  |
| Groups           | Group                     | RU      | `gitlab_group` of `group-foundation` and `group-topology`                                                                             |
| Project Planning | Label                     | CRUD    | `gitlab_group_label` of `group-gitlab-configuration`                                                                                  |
| Project Planning | Work Item                 | CRUD    | `gitlab_project_milestone` of the repositories below `personal`                                                                       |

1. Only `parent-group-governance` declares `inbound_job_token_scope_project_ids`. All other callers of `provisioner-gitlab-project` retain the default `[]`. `gitlab_project_job_token_scope` therefore provisions no resources for those callers.
2. `platform-observability` grants Remote Mirror and Remote Mirror Public Key for the GitHub mirror of `provisioner-github-mirror`.
3. Terraform State permissions omit Delete because the owner deletes a superseded state directly through the GitLab web UI.
4. Catalog Resource offers Create and Delete alone.
5. A downstream token MUST NOT grant Group Read. `generic-agent-criteria-source` reads the public group `csning1998-lab/platform-engineering-lab` through `data.gitlab_group` without Group Read.
6. A downstream project MUST be created initially through the governance identity, because a project-scoped token cannot exist before project creation. Branch Read and the User tab resources other than User therefore belong to `parent-group-governance` alone.
7. The GitLab permission specification places the project milestone endpoints `/projects/:id/milestones` under the Work Item resource.

### Item E. Membership Scope

1. A selected group extends every project permission of the token to every project and subgroup below the group.
2. The `parent-group-governance` token therefore reaches the state, variables, and remote mirrors of every repository in `csning1998-lab`.
3. The chosen path accepts the group wide scope, since the governance identity creates every project and the `administrator` identity writes every repository token.
4. The associated cost is a governance token whose reach exceeds the state of `parent-group-governance`. Separate tokens for the state backend and the `gitlab` provider would narrow the reach, at the cost of `vault-proxy-env` exporting two tokens per identity.
5. The `personal` token selects the subgroup `csning1998-lab/personal` and serves every repository below the subgroup through one identity. A personal repository joins without a change to `workstation-topology.yaml` or this document. The associated cost is a shared token without isolation between personal repositories.

## Section 4. Procedures

### Item A. Creation

1. The owner MUST create the token at the URL specified in item 5 of Section 1, assigning the name and description defined in Section 2 Item A.
2. The owner MUST configure an expiration period of at most 365 days.
3. The owner MUST select the groups and projects listed in the Selected memberships column of Section 2 Item A.
4. The owner MUST grant the actions of the corresponding owner code column on each tab of the resource selector: Group and project (Section 3 Item A), User (Section 3 Item B), and Global (Section 3 Item C).

### Item B. Writing to the Bastion Vault

The following command ingests the token from a local file without displaying its value in the terminal. The `pipefail` option halts execution if reading the file fails.

```bash
eval "$(vault-proxy-env administrator)"
set -o pipefail
f="$HOME/Vaults/Tokens/terraform-state-backend-<repository name>"
[ -s "$f" ] && tr -d '\n' < "$f" | vault kv put -mount=secret <owner code>/terraform/state-backend token=- >/dev/null \
  && vault kv get -mount=secret -field=token <owner code>/terraform/state-backend | tr -d '\n' | wc -c
set +o pipefail
```

1. The printed character count MUST be greater than zero.
2. An erroneous value MUST be removed using `vault kv metadata delete -mount=secret <owner code>/terraform/state-backend` before writing the corrected value, because Vault KV-v2 retains historical versions.
3. A shell loop variable in zsh MUST NOT use the name `path`, because zsh binds `path` directly to the environment variable `PATH`.

### Item C. Verification

The following command prints only HTTP response status codes.

```bash
eval "$(vault-proxy-env administrator)"
t="$(vault kv get -mount=secret -field=token <owner code>/terraform/state-backend)"
for s in user metadata projects/<project ID>/push_rule projects/<project ID>/terraform/state/<own state> \
  projects/86417732/terraform/state/group-topology; do
  printf '%s ' "$s"; curl -s -o /dev/null -w '%{http_code}\n' -H "PRIVATE-TOKEN: ${t}" "https://gitlab.com/api/v4/${s}"
done
unset t
```

1. Probing `user`, `metadata`, and the own state endpoint MUST return HTTP `200`.
2. Probing the `push_rule` endpoint MUST NOT return HTTP `403`.
3. Probing the `parent-group-governance` state endpoint MUST return HTTP `403` for every downstream token.

### Item D. Replacement and Rotation

1. The owner MUST replace each token prior to the expiration date, and after every change of Section 3.
2. A replacement creates a new token through Item A, overwrites the local token file, writes the token through Item B, and verifies the token through Item C.
3. The owner MUST revoke the superseded token on the management page in item 5 of Section 1 after the verification.
4. A replacement does not change Terraform layer configurations or Vault access policies.

## Section 5. Provider Requirements

The `gitlab` provider 19.2.0 issues the following requests, which determine the permissions of Section 3 beyond the managed resources.

1. The provider requests `GET /user` during configuration, since the `early_auth_check` attribute defaults to `true`. The request requires User Read.
2. `gitlab_branch_protection` and `gitlab_group` request `GET /metadata` to detect GitLab EE. The request requires Metadata Read.
3. `gitlab_project` requests `GET /projects/:id/push_rule` on every refresh, and `gitlab_group` requests `GET /groups/:id/push_rule`. The provider accepts HTTP `404` alone, hence Push Rule Read is required although GitLab.com Free does not offer push rules.
4. `gitlab_user_runner` updates the runner through `PUT /runners/:id`, which requires Runner Update.
5. `gitlab_project_cicd_catalog` reads the catalog status through the GraphQL field `project(fullPath) { isCatalogResource }`, which Project Read covers.
6. `gitlab_project` creation waits for the default branch protection through `GET /projects/:id/repository/branches/:branch`, which requires Branch Read.
7. A token without a required permission receives HTTP `403` with the error `insufficient_granular_scope`, and the error description names the missing permission.
