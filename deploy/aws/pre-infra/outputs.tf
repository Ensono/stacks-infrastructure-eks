# DNS
output "dns_hostedzone_ns_records" {
  description = "The nameserver records to add to the parent as an NS record"
  value       = var.dns_create_hostedzone ? aws_route53_zone.environment.0.name_servers : []
}

# K8s Roles
output "aws_k8s_roles" {
  description = "The Roles Map for managing K8s Clusters"

  value = {
    for role_map_key, role_map in local.k8s_role_map : role_map_key => merge(
      role_map,
      { role_arn = aws_iam_role.k8s_role[role_map_key].arn },
    ) if length(role_map.users) > 0
  }
}

# Container Registry
output "aws_ecr_pull_push_user_id" {
  description = "The Access Key ID of the ECR Pull/Push User"
  value       = var.container_registry_pull_push_user ? aws_iam_access_key.ecr_pull_push[0].id : ""
}

output "aws_ecr_pull_push_user_secret" {
  description = "The Secret Access Key of the ECR Pull/Push User"
  value       = var.container_registry_pull_push_user ? aws_iam_access_key.ecr_pull_push[0].secret : ""

  sensitive = true
}
