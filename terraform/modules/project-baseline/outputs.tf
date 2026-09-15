
output "project_id" {
  description = "Numeric identifier of the provisioned GitLab project."
  value       = gitlab_project.this.id
}

output "repository_ssh_url" {
  description = "SSH repository clone URI."
  value       = gitlab_project.this.ssh_url_to_repo
}

output "repository_http_url" {
  description = "HTTP repository clone URI."
  value       = gitlab_project.this.http_url_to_repo
}

output "full_path" {
  description = "Fully qualified namespace path of the project."
  value       = gitlab_project.this.path_with_namespace
}
