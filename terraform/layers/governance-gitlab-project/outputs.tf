
output "project_id" {
  description = "Numeric identifier of the project 'parent-group-governance'."
  value       = module.provisioner_gitlab_project.project_id
}
