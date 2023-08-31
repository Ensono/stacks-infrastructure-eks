########################################
# EKS INFRA OUTPUT
#########################################
output "cluster_id" {
  description = "EKS cluster ID."
  value       = module.amido_stacks_infra.cluster_id
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane."
  value       = module.amido_stacks_infra.cluster_endpoint
}


output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane."
  value       = module.amido_stacks_infra.cluster_security_group_id
}

output "config_map_aws_auth" {
  description = "A kubernetes configuration to authenticate to this EKS cluster."
  value       = module.amido_stacks_infra.config_map_aws_auth
}

output "region" {
  description = "AWS region"
  value       = var.region
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.amido_stacks_infra.cluster_name
}

output "cluster_certificate_authority_data" {
  description = "base64 encoded certificate data required to communicate with your cluster"
  value       = module.amido_stacks_infra.cluster_certificate_authority_data
}

#######
# OIDC 
#######

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.amido_stacks_infra.cluster_oidc_issuer_url
}

output "cluster_oidc_provider" {
  description = "OpenID Connect identity provider without leading http"
  value = module.amido_stacks_infra.cluster_oidc_provider
}

output "cluster_oidc_provider_arn" {
  description = "OpenID Connect identity provider ARN"
  value = module.amido_stacks_infra.cluster_oidc_provider_arn
}

################
# Route 53 Zones
#################
output "route53_zone_zone_id" {
  description = "Zone ID of Route53 zone"
  value       = var.enable_zone ? module.amido_stacks_infra.route53_zone_zone_id : null
}

output "route53_zone_name_servers" {
  description = "Name servers of Route53 zone"
  value       = var.enable_zone ? module.amido_stacks_infra.route53_zone_name_servers : null
}

output "route53_zone_name" {
  description = "Name of the Route53 zone."
  value       = var.enable_zone ? module.amido_stacks_infra.route53_zone_name : null
}

##############
# Cloud Watch
###############
output "cloudwatch_log_group_arn" {
  description = "ARN of the cloudwatch log group."
  value       = aws_cloudwatch_log_group.amido_stacks_eks.arn
}
