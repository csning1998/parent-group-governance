
locals {
  # Target: group-foundation state, hosted under this GitLab project.
  _state_base = "https://gitlab.com/api/v4/projects/86417732/terraform/state"
  _state_auth = module.local_credential_contexts.state_auth_gitlab_saas
}

locals {
  # parent is null for a subgroup nested directly under the top-level group, or the key of
  # another entry in this same map for a nested subgroup.
  subgroups = {
    template = {
      name        = "Template"
      description = "Project templates and boilerplate code."
      visibility  = "public"
      parent      = null
    }
    personal = {
      name        = "Personal"
      description = "Personal projects and archives."
      visibility  = "public"
      parent      = null
    }
    "gt-omscs" = {
      name        = "GT-OMSCS"
      description = "GT OMSCS coursework, side projects, and personal-relavant training."
      visibility  = "public"
      parent      = "personal"
    }
    rug = {
      name        = "RUG"
      description = "RUG course assignments and side projects."
      visibility  = "private"
      parent      = "personal"
    }
    "fjcu-colab" = {
      name        = "FJCU-colab"
      description = "Collaborative projects and joint research initiatives."
      visibility  = "public"
      parent      = null
    }
    "platform-engineering-lab" = {
      name        = "Platform Engineering Lab"
      description = "A centralized workspace for a personally crafted, production-grade internal development platform."
      visibility  = "public"
      parent      = null
    }
    terraform = {
      name        = "Terraform"
      description = "Terraform components related to platform engineering"
      visibility  = "public"
      parent      = "platform-engineering-lab"
    }
  }

  top_level_subgroups = { for k, v in local.subgroups : k => v if v.parent == null }
  nested_subgroups    = { for k, v in local.subgroups : k => v if v.parent != null }
}
