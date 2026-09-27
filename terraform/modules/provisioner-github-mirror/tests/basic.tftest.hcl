
mock_provider "gitlab" {
  mock_data "gitlab_project" {
    defaults = {
      visibility  = "private"
      description = "Mock GitLab project description"
    }
  }
}

mock_provider "github" {}

run "default_github_mirror" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name  = "example-repository"
      owner = "example-org"
    }
  }

  assert {
    condition     = github_repository.this.name == "example-repository"
    error_message = "github repository name must match github_repository.name"
  }

  assert {
    condition     = github_repository.this.visibility == "private"
    error_message = "github repository visibility must default to private from gitlab project"
  }

  assert {
    condition     = github_repository.this.description == "Mock GitLab project description"
    error_message = "github repository description must default to gitlab project description"
  }

  assert {
    condition     = github_repository.this.auto_init == false
    error_message = "auto_init must stay disabled"
  }

  assert {
    condition     = github_repository.this.archive_on_destroy == true
    error_message = "archive_on_destroy must stay enabled"
  }

  assert {
    condition     = gitlab_project_push_mirror.this.url == "ssh://git@github.com/example-org/example-repository.git"
    error_message = "push mirror url must target github ssh endpoint with owner and repo name"
  }

  assert {
    condition     = gitlab_project_push_mirror.this.auth_method == "ssh_public_key"
    error_message = "auth_method must use ssh_public_key"
  }

  assert {
    condition     = github_repository_deploy_key.this.read_only == false
    error_message = "deploy key must be read-write"
  }

  assert {
    condition     = output.github_repository.name == "example-repository"
    error_message = "output.github_repository.name must match"
  }
}

run "public_visibility" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name       = "example-repository"
      owner      = "example-org"
      visibility = "public"
    }
  }

  assert {
    condition     = github_repository.this.visibility == "public"
    error_message = "public visibility must pass through to github repository"
  }
}

run "internal_visibility_mapping" {
  command = plan

  variables {
    gitlab_project_id = "10002"
    github_repository = {
      name        = "example-internal-repo"
      owner       = "example-org"
      visibility  = "internal"
      description = "Internal example repository"
    }
  }

  assert {
    condition     = github_repository.this.visibility == "private"
    error_message = "gitlab internal visibility must map to github private visibility"
  }

  assert {
    condition     = github_repository.this.description == "Internal example repository"
    error_message = "description must match the provided value"
  }
}

run "rejects_invalid_visibility" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name       = "example-repository"
      owner      = "example-org"
      visibility = "bogus"
    }
  }

  expect_failures = [var.github_repository.visibility]
}

run "rejects_invalid_github_owner" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name  = "example-repository"
      owner = "-invalid-owner-"
    }
  }

  expect_failures = [var.github_repository.owner]
}

run "rejects_excessive_name_length" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name  = "this-is-an-extremely-long-github-repository-name-that-definitely-exceeds-the-maximum-limit-of-one-hundred-characters-allowed-by-github"
      owner = "example-org"
    }
  }

  expect_failures = [var.github_repository.name]
}

run "rejects_excessive_description_length" {
  command = plan

  variables {
    gitlab_project_id = "10001"
    github_repository = {
      name        = "example-repository"
      owner       = "example-org"
      description = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. Extra text to exceed 350 characters limit."
    }
  }

  expect_failures = [var.github_repository.description]
}
