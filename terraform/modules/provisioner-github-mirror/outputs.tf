
output "github_repository" {
  description = "Provides metadata and endpoints of the provisioned GitHub repository."
  value = {
    name          = github_repository.this.name
    full_name     = github_repository.this.full_name
    html_url      = github_repository.this.html_url
    ssh_clone_url = github_repository.this.ssh_clone_url
  }
}

output "gitlab_project_push_mirror" {
  description = "Provides metadata of the provisioned GitLab project push mirror."
  value = {
    mirror_id = gitlab_project_push_mirror.this.mirror_id
  }
}
