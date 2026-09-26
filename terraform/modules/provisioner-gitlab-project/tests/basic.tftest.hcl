
mock_provider "gitlab" {}

# meta-platform/terraform/layers/meta-gitlab-project: module.provisioner_gitlab_project
run "meta_platform_project" {
  command = plan

  variables {
    name         = "meta-platform"
    description  = "Shared platform infrastructure and GitLab group governance for the csning1998-lab group."
    visibility   = "public"
    namespace_id = 142251633
    extra_variables = {
      CLAUDE_API_KEY = "fake-claude-key"
    }
  }

  assert {
    condition     = gitlab_project.this.merge_method == "ff"
    error_message = "merge_method must stay fast-forward-only"
  }

  assert {
    condition     = gitlab_branch_protection.main.branch == "main"
    error_message = "branch protection must target main"
  }

  assert {
    condition     = gitlab_branch_protection.main.allow_force_push == false
    error_message = "force push to main must stay disabled"
  }

  assert {
    condition     = length(gitlab_project_variable.extra) == 1
    error_message = "a non-empty extra_variables map must create exactly one project variable"
  }

  assert {
    condition     = gitlab_project_variable.extra["CLAUDE_API_KEY"].masked == true && gitlab_project_variable.extra["CLAUDE_API_KEY"].hidden == true
    error_message = "a project variable must stay masked and hidden"
  }
}

run "no_extra_variables" {
  command = plan

  variables {
    name         = "meta-platform"
    namespace_id = 142251633
  }

  assert {
    condition     = length(gitlab_project_variable.extra) == 0
    error_message = "omitting extra_variables must create zero project variables"
  }

  assert {
    condition     = gitlab_project.this.visibility_level == "private"
    error_message = "visibility must default to private"
  }

  assert {
    condition     = gitlab_project.this.description == ""
    error_message = "description must default to an empty string"
  }
}

run "multiple_extra_variables" {
  command = plan

  variables {
    name         = "meta-platform"
    namespace_id = 142251633
    extra_variables = {
      CLAUDE_API_KEY = "fake-claude-key"
      GEMINI_API_KEY = "fake-gemini-key"
    }
  }

  assert {
    condition     = length(gitlab_project_variable.extra) == 2
    error_message = "setting two extra_variables must create exactly two project variables"
  }

  assert {
    condition     = contains(keys(gitlab_project_variable.extra), "GEMINI_API_KEY")
    error_message = "the created variable must contain GEMINI_API_KEY"
  }
}

run "custom_squash_and_pipeline_gate" {
  command = plan

  variables {
    name                                  = "second-brain"
    namespace_id                          = 83198964
    squash_commit_template                = "%%{title} (!%%{issue_iid})"
    only_allow_merge_if_pipeline_succeeds = false
  }

  assert {
    condition     = gitlab_project.this.squash_commit_template == "%%{title} (!%%{issue_iid})"
    error_message = "a custom squash_commit_template must pass through unchanged"
  }

  assert {
    condition     = gitlab_project.this.only_allow_merge_if_pipeline_succeeds == false
    error_message = "a repository without CI must be able to disable the pipeline-success gate"
  }
}

run "internal_visibility" {
  command = plan

  variables {
    name         = "credentials"
    namespace_id = 86417732
    visibility   = "internal"
  }

  assert {
    condition     = gitlab_project.this.visibility_level == "internal"
    error_message = "internal must be an accepted visibility value"
  }
}

run "rejects_invalid_visibility" {
  command = plan

  variables {
    name         = "meta-platform"
    namespace_id = 142251633
    visibility   = "bogus"
  }

  expect_failures = [var.visibility]
}
