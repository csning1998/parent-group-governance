# provisioner-github-mirror

## Section 1. Purpose

A GitHub mirror provisioner is a Terraform module which registers a downstream GitHub repository, establishes a GitLab project SSH push mirror, and attaches the GitLab-generated deploy key with write permissions to GitHub.

This module provides a unified implementation for mirroring GitLab projects to GitHub across `csning1998-lab`. Every consuming project layer that requires public or backup mirroring MUST invoke this module.

## Section 2. Interface

### Item A. Usage

```hcl
module "github_mirror" {
    source  = "gitlab.com/csning1998-lab/provisioner-github-mirror/gitlab"
    version = "~> 0.1.0"

    gitlab_project_id = module.provisioner_gitlab_project.project_id

    github_repository = {
        name        = var.gitlab_project_name
        owner       = var.github_owner
        visibility  = var.visibility
        description = var.description
    }
}
```

A caller inside `parent-group-governance` MAY reference this module through the relative path `../../modules/provisioner-github-mirror`.

### Item B. Inputs

#### Item B.1. Variable `gitlab_project_id`

The variable `gitlab_project_id` defines the target GitLab project identifier.

| Type     | Default      | Description                                            |
| -------- | ------------ | ------------------------------------------------------ |
| `string` | **required** | GitLab project numeric identifier or URL-encoded path. |

#### Item B.2. Variable `github_repository`

The variable `github_repository` defines target GitHub repository attributes and push mirror options.

| Field                     | Type               | Default      | Description                                                                                                                                |
| ------------------------- | ------------------ | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `name`                    | `string`           | **required** | Exact name of the GitHub repository without group namespace prefix (maximum 100 characters).                                               |
| `owner`                   | `string`           | **required** | GitHub account or organization login hosting the mirrored repository.                                                                      |
| `visibility`              | `optional(string)` | `null`       | Repository visibility level. When omitted, inherits from the GitLab project visibility. Permitted values: `public`, `internal`, `private`. |
| `description`             | `optional(string)` | `null`       | Repository description published to GitHub (maximum 350 characters). When omitted, inherits from the GitLab project description.           |
| `only_protected_branches` | `optional(bool)`   | `false`      | Whether to mirror only protected branches from GitLab to GitHub.                                                                           |
| `keep_divergent_refs`     | `optional(bool)`   | `false`      | Whether to keep divergent refs on the GitHub repository.                                                                                   |

### Item C. Outputs

#### Item C.1. Output `github_repository`

The output `github_repository` provides metadata and endpoints of the provisioned GitHub repository.

| Field           | Type     | Description                                                    |
| --------------- | -------- | -------------------------------------------------------------- |
| `name`          | `string` | The name of the GitHub repository.                             |
| `full_name`     | `string` | The full name of the GitHub repository in `owner/name` format. |
| `html_url`      | `string` | The HTTPS URL of the GitHub repository.                        |
| `ssh_clone_url` | `string` | The SSH clone URL of the GitHub repository.                    |

#### Item C.2. Output `gitlab_project_push_mirror`

The output `gitlab_project_push_mirror` provides metadata of the provisioned GitLab project push mirror.

| Field       | Type     | Description                                              |
| ----------- | -------- | -------------------------------------------------------- |
| `mirror_id` | `string` | The unique identifier of the GitLab project push mirror. |

## Section 3. Operational Contracts

The caller MUST ensure that the GitHub provider is authenticated with an access token possessing repository administration privileges (`repo` scope).

The module automatically embeds official GitHub SSH host key fingerprints (`ssh-ed25519`, `ecdsa-sha2-nistp256`) into the GitLab push mirror configuration.

## Section 4. Brownfield Migration

A caller managing a pre-existing GitHub repository, GitLab push mirror, or GitHub deploy key MUST declare `import` blocks to adopt existing remote infrastructure into Terraform state.

### Item A. Import Block Configuration

```hcl
import {
    to = module.github_mirror.github_repository.this
    id = var.gitlab_project_name
}

import {
    to = module.github_mirror.gitlab_project_push_mirror.this
    id = "<gitlab_project_id>:<mirror_id>"
}

import {
    to = module.github_mirror.github_repository_deploy_key.this
    id = "${var.gitlab_project_name}:<deploy_key_id>"
}
```

### Item B. Import Identifier Specification

1.  The GitHub repository identifier MUST be the repository name without the owner prefix.
2.  The GitLab push mirror identifier MUST use the composite format `<gitlab_project_id>:<mirror_id>`, queryable via `glab api projects/<project_id>/remote_mirrors`.
3.  The GitHub deploy key identifier MUST use the composite format `<repository_name>:<key_id>`, queryable via `gh api repos/<owner>/<repo>/keys`.
