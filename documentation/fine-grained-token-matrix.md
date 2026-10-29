# Fine-Grained Token Matrix

This document defines the GitLab.com fine-grained personal access tokens across group repositories, the corresponding Bastion Vault storage paths, and the permissions granted to each token.

## Section 1. Context and Constraints

1. The current constraint is the GitLab.com Free tier plan of the group, which provides neither project access tokens nor group access tokens.
2. The chosen path provisions one fine-grained personal access token per repository under the owner account. Setting `access` to selected memberships limits each downstream token to its own project.
3. Each token provides `TF_HTTP_PASSWORD` for the Terraform HTTP state backend and supplies authentication for the `gitlab` provider across the layers of that repository.
4. The associated cost is that each token attaches to the personal owner account, expires within 365 days, and requires manual rotation.
5. The owner manages tokens through <https://gitlab.com/-/user_settings/personal_access_tokens?state=active&sort=expires_asc>, which lists active tokens ordered by expiration date.
6. Permission names conform to the GitLab fine-grained permission specifications for the [REST API](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_rest/) and [GraphQL API](https://docs.gitlab.com/auth/tokens/fine_grained_access_tokens_graphql/).

## Section 2. Token Registry

### Item A. Names and Paths

1. A token name MUST follow `terraform-state-backend-<repository name>`. The token name serves display purposes only, placing the kind before the repository name to match operator Proxy identity conventions.
2. A token description MUST be `Bastion Vault secret/<owner code>/terraform/state-backend` to record the exact path hosting the token.
3. The token MUST reside in the `token` field under `secret/<owner code>/terraform/state-backend`. The `administrator` proxy identity writes to this path.

| Token name                                              | Owner code                      | Project ID | Selected memberships                                                  | Reading identities                                                  |
| ------------------------------------------------------- | ------------------------------- | ---------- | --------------------------------------------------------------------- | ------------------------------------------------------------------- |
| `terraform-state-backend-parent-group-governance`       | `parent-group-governance`       | `86417732` | Group `csning1998-lab` and project `parent-group-governance`          | `credential-distributor`, `administrator`                           |
| `terraform-state-backend-platform-foundation`           | `platform-foundation`           | `84608830` | Project `csning1998-lab/platform-engineering-lab/platform-foundation` | `platform-foundation`, `credential-distributor-platform-foundation` |
| `terraform-state-backend-on-premise-gitlab-deployment`  | `opgitlab`                      | `82448331` | Project `on-premise-gitlab-deployment`                                | `credential-distributor-opgitlab`, `consumer-opgitlab`              |
| `terraform-state-backend-gitlab-ci-with-code-reviewer`  | `gitlab-ci-with-code-reviewer`  | `83083739` | Project `gitlab-ci-with-code-reviewer`                                | `credential-distributor-gitlab-ci-with-code-reviewer`               |
| `terraform-state-backend-generic-agent-criteria-source` | `generic-agent-criteria-source` | `85419450` | Project `generic-agent-criteria-source`                               | `credential-distributor-generic-agent-criteria-source`              |
| `terraform-state-backend-platform-observability`        | `platform-observability`        | `87321619` | Project `platform-observability`                                      | `consumer-platform-observability`                                   |

### Item B. Status

| Token                                                   | Vault path state                                                                                           | Verification (2026-10-28)                              |
| ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | ------------------------------------------------------ |
| `terraform-state-backend-parent-group-governance`       | Not written. The path holds the shared token until every downstream repository runs with its own identity. | Not run                                                |
| `terraform-state-backend-platform-foundation`           | Written                                                                                                    | Own state `200`, `parent-group-governance` state `403` |
| `terraform-state-backend-on-premise-gitlab-deployment`  | Written                                                                                                    | `parent-group-governance` state `403`                  |
| `terraform-state-backend-gitlab-ci-with-code-reviewer`  | Not written. The governance layer of the repository currently reads this path, postponing the cutover.     | Not run                                                |
| `terraform-state-backend-generic-agent-criteria-source` | Written                                                                                                    | Own state `200`, `parent-group-governance` state `403` |
| `terraform-state-backend-platform-observability`        | Written                                                                                                    | `parent-group-governance` state `403`                  |

## Section 3. Permission Matrix

### Item A. Project Permissions

Column headers indicate owner codes. The value `Y` grants the permission, while `-` withholds the permission.

| Resource                  | Actions                      | Terraform consumer                                                       | `parent-group-governance` | `platform-foundation` | `opgitlab` | `gitlab-ci-with-code-reviewer` | `generic-agent-criteria-source` | `platform-observability` |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------ | ------------------------- | --------------------- | ---------- | ------------------------------ | ------------------------------- | ------------------------ |
| Terraform State           | Read, Create, Lock           | The HTTP backend of every layer                                          | Y                         | Y                     | Y          | Y                              | Y                               | Y                        |
| Project                   | Read, Update                 | `gitlab_project`, `data.gitlab_project`                                  | Y                         | Y                     | Y          | Y                              | Y                               | Y                        |
| Variable                  | Read, Create, Update, Delete | `gitlab_project_variable` of the project, WIF, and code reviewer modules | Y                         | Y                     | Y          | Y                              | Y                               | Y                        |
| Protected Branch          | Read, Update                 | `gitlab_branch_protection`                                               | Y                         | Y                     | Y          | Y                              | Y                               | Y                        |
| Branch                    | Protect                      | `gitlab_branch_protection`                                               | Y                         | Y                     | Y          | Y                              | Y                               | Y                        |
| Job Token Scope Allowlist | Read, Create, Delete         | `gitlab_project_job_token_scope`                                         | Y                         | -                     | -          | -                              | -                               | -                        |
| Remote Mirror             | Read, Create, Update, Delete | `gitlab_project_push_mirror`                                             | Y                         | Y                     | Y          | Y                              | Y                               | -                        |
| Remote Mirror Public Key  | Read                         | `data.gitlab_project_mirror_public_key`                                  | Y                         | Y                     | Y          | Y                              | Y                               | -                        |
| Catalog Resource          | Create, Delete               | `gitlab_project_cicd_catalog`, through the GraphQL API                   | -                         | -                     | -          | Y                              | -                               | -                        |

1. Only `parent-group-governance` declares `inbound_job_token_scope_project_ids`. All other callers of `provisioner-gitlab-project` retain the default `[]`. `gitlab_project_job_token_scope` therefore provisions no resources for those callers.
2. `platform-observability` invokes `provisioner-gitlab-project` alone, requiring no Remote Mirror permissions.
3. Terraform State permissions omit Delete because the owner deletes a superseded state directly through the GitLab web UI.

### Item B. Group and User Permissions

Only `terraform-state-backend-parent-group-governance` grants the following group and user-level permissions.

| Resource | Actions                      | Access                          | Terraform consumer                                                            |
| -------- | ---------------------------- | ------------------------------- | ----------------------------------------------------------------------------- |
| Group    | Read, Update                 | Selected memberships, the group | `gitlab_group` of `group-foundation` and `group-topology`                     |
| Group    | Create                       | User                            | Subgroups of `group-topology` through `POST /groups`                          |
| Label    | Read, Create, Update, Delete | Selected memberships, the group | `gitlab_group_label` of `group-gitlab-configuration`                          |
| Variable | Read, Create, Update, Delete | Selected memberships, the group | `gitlab_group_variable` of `group-gitlab-configuration`                       |
| Runner   | Create                       | User                            | `gitlab_user_runner` of `group-gitlab-runner` through `POST /user/runners`    |
| Runner   | Read, Delete                 | Selected memberships, the group | `gitlab_user_runner` through `GET` and `DELETE /runners/:id`                  |
| Project  | Create                       | User                            | The first apply or a rebuild of a downstream project through `POST /projects` |

1. A downstream token MUST NOT grant Group Read. For example, `generic-agent-criteria-source` reads the public group `csning1998-lab/platform-engineering-lab` via `data.gitlab_group`, and this read succeeded with HTTP `200` without Group Read permissions on 2026-10-28.
2. A downstream project MUST be created initially through the governance identity, because a project-scoped token cannot exist before project creation.

## Section 4. Procedures

### Item A. Creation

1. The owner MUST create the token at the URL specified in item 5 of Section 1, assigning the name and description defined in Section 2 Item A.
2. The owner MUST configure an expiration period of at most 365 days and schedule a calendar reminder prior to expiration.
3. The owner MUST configure the memberships and permissions specified in the corresponding owner code column of Section 3.

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

The following command prints only HTTP response status codes. The Basic authentication username `gitlab-ci-token` mirrors the authentication pattern of the Terraform HTTP backend.

```bash
eval "$(vault-proxy-env administrator)"
t="$(vault kv get -mount=secret -field=token <owner code>/terraform/state-backend)"
for s in <project ID>/terraform/state/<own state> 86417732/terraform/state/group-topology; do
  printf '%s ' "$s"; curl -s -o /dev/null -w '%{http_code}\n' -u "gitlab-ci-token:${t}" "https://gitlab.com/api/v4/projects/${s}"
done
unset t
```

1. Probing the own state endpoint of the repository MUST return HTTP `200`.
2. Probing the `parent-group-governance` state endpoint MUST return HTTP `403` for all downstream tokens.

### Item D. Rotation

1. The owner MUST rotate each token prior to its expiration date via the management page in item 5 of Section 1, writing the renewed token using Item B.
2. Token rotation requires no changes to Terraform layer configurations or Vault access policies.

## Section 5. Unverified Points

1. The update endpoint for `gitlab_user_runner` (`PUT /runners/:id`) does not appear in the fine-grained REST permission reference.
2. The GraphQL query used to inspect catalog resources does not appear in the fine-grained GraphQL permission reference.
3. Official documentation does not specify whether project permissions granted under a selected group propagate across all projects within that group, which defines the effective boundary of the `parent-group-governance` token.
4. Web UI support for combining User-level access with selected group memberships remains unverified, although the underlying API accepts an array of `granular_scopes`.
5. An omitted permission manifests as an HTTP `403` error during `terraform plan`, allowing the owner to add the exact permission identified in the error output.
