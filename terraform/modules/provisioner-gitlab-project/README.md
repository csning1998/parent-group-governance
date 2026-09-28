# provisioner-gitlab-project

## Section 1. Purpose

A GitLab project provisioner is a Terraform module which instantiates a standardized GitLab project repository, configures branch protection policies on the default branch, injects project-level CI/CD variables, and manages inbound CI job token access scopes.

This module enforces centralized repository baseline standards across `csning1998-lab`. Consuming layers MUST invoke this module to provision managed GitLab repositories.

## Section 2. Interface

### Item A. Usage

```hcl
module "provisioner_gitlab_project" {
    source  = "gitlab.com/csning1998-lab/provisioner-gitlab-project/gitlab"
    version = "~> 0.2.0"

    name         = var.project_name
    description  = var.project_description
    visibility   = var.visibility
    namespace_id = var.namespace_id

    only_allow_merge_if_pipeline_succeeds = true
    inbound_job_token_scope_project_ids   = var.inbound_job_token_scope_project_ids
}
```

A caller inside `parent-group-governance` can directly reference this module through the relative path `../../modules/provisioner-gitlab-project`.

### Item B. Inputs

The module accepts configuration variables specifying project identity, merge criteria, access boundaries, and CI token permissions.

| Name                                    | Type           | Default      | Description                                                                                                        |
| --------------------------------------- | -------------- | ------------ | ------------------------------------------------------------------------------------------------------------------ |
| `name`                                  | `string`       | **required** | Project name and repository path slug identifier.                                                                  |
| `description`                           | `string`       | `""`         | Project description displayed on the GitLab project overview page.                                                 |
| `visibility`                            | `string`       | `"private"`  | Visibility level of the project. Permitted values: `public`, `internal`, and `private`.                            |
| `namespace_id`                          | `number`       | **required** | Numeric identifier of the target parent namespace or subgroup.                                                     |
| `only_allow_merge_if_pipeline_succeeds` | `bool`         | `true`       | Pipeline completion merge gate. Set to `false` for repositories lacking a `.gitlab-ci.yml` pipeline configuration. |
| `squash_commit_template`                | `string`       | `"%{title}"` | Commit message template utilized for squashed merge commits.                                                       |
| `extra_variables`                       | `map(string)`  | `{}`         | Map of extra project CI/CD variables. Values are masked and hidden.                                                |
| `inbound_job_token_scope_project_ids`   | `list(number)` | `[]`         | List of numeric project IDs permitted to authenticate inbound requests via `CI_JOB_TOKEN`.                         |

### Item C. Outputs

The module exports identifiers and clone URIs of the provisioned project repository.

| Name                  | Type     | Description                                           |
| --------------------- | -------- | ----------------------------------------------------- |
| `project_id`          | `string` | Numeric identifier of the provisioned GitLab project. |
| `repository_ssh_url`  | `string` | SSH git clone endpoint.                               |
| `repository_http_url` | `string` | HTTPS git clone endpoint.                             |
| `full_path`           | `string` | Fully qualified namespace path of the project.        |

## Section 3. Governance Policies

The module enforces strict governance baselines on every provisioned repository:

- Fast-forward merge method (`ff`) is permanently enabled.
- Branch protection on `main` prohibits direct pushes (`no one`) and restricts merge rights to `maintainer`.
- Force push operations on `main` are permanently disabled.
- Shared runners and repository wikis are disabled by default.
- Extra CI/CD variables are provisioned with `masked = true`, `hidden = true`, and `raw = true`.

## Section 4. Brownfield Migration

A caller managing a pre-existing GitLab project is suggested to declare `import` blocks to adopt existing resources into Terraform state.

### Item A. Import Block Configuration

```hcl
import {
    to = module.provisioner_gitlab_project.gitlab_project.this
    id = "<project_id>"
}

import {
    to = module.provisioner_gitlab_project.gitlab_branch_protection.main
    id = "<project_id>:main"
}
```
