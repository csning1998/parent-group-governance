
output "group_id" {
  description = "Numeric identifier of the top-level group 'csning1998-lab', exported for downstream layer consumption via remote state."
  value       = gitlab_group.this.id
}

output "full_path" {
  description = "Fully qualified namespace path of the top-level group 'csning1998-lab'."
  value       = gitlab_group.this.full_path
}
