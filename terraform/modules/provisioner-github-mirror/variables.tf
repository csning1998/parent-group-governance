
variable "gitlab_project_id" {
  description = "Specifies the GitLab project numeric identifier or URL-encoded path."
  type        = string
}

variable "github_repository" {
  description = "Specifies target GitHub repository attributes and push mirror options."
  type = object({
    name                    = string
    owner                   = string
    visibility              = optional(string)
    description             = optional(string)
    only_protected_branches = optional(bool, false)
    keep_divergent_refs     = optional(bool, false)
  })

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]{1,100}$", var.github_repository.name))
    error_message = "github_repository.name must contain only alphanumeric characters, periods, underscores, or hyphens, and must not exceed 100 characters."
  }

  validation {
    condition     = can(regex("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$", var.github_repository.owner))
    error_message = "github_repository.owner must be a GitHub login of 1 to 39 characters. A hyphen must not be the first or last character."
  }

  validation {
    condition     = var.github_repository.visibility == null ? true : contains(["public", "internal", "private"], var.github_repository.visibility)
    error_message = "github_repository.visibility must be one of: public, internal, private."
  }

  validation {
    condition     = var.github_repository.description == null ? true : length(var.github_repository.description) <= 350
    error_message = "github_repository.description must not exceed 350 characters."
  }
}
