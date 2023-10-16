output "region" {
  description = "AWS region"
  value       = var.region
}

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
  value       = module.amido_stacks_infra.cluster_oidc_provider
}

output "cluster_oidc_provider_arn" {
  description = "OpenID Connect identity provider ARN"
  value       = module.amido_stacks_infra.cluster_oidc_provider_arn
}

##############
# Cloud Watch
##############
output "cloudwatch_log_group_arn" {
  description = "ARN of the cloudwatch log group."
  value       = aws_cloudwatch_log_group.amido_stacks_eks.arn
}

###############################
# AWS Load Balancer Controller
###############################
output "aws_lb_controller_role_arn" {
  description = "The ARN of the AWS Role created for aws-loadbalancer-controller to use"
  value       = var.aws_lb_controller_enabled == 1 ? module.aws_lb_controller_irsa_iam_role[0].irsa_role_arn : ""
}

###############
# External DNS
###############
output "external_dns_role_arn" {
  description = "The ARN of the AWS Role created for External DNS to use"
  value       = module.external_dns_irsa_iam_role[0].irsa_role_arn
}

###############
# EBS CSI Driver
###############
output "ebs_csi_driver_role_arn" {
  description = "The ARN of the AWS Role created for EBS CSI driver to use"
  value       = module.ebs_csi_irsa_iam_role.irsa_role_arn
}

###############
# Cert Manager
###############
output "cert_manager_role_arn" {
  description = "The ARN of the AWS Role created for cert manager to use"
  value       = module.cert_manager_irsa_iam_role.irsa_role_arn
}