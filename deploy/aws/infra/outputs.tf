output "region" {
  description = "AWS region"
  value       = var.region
}

#########################################
# VPC OUTPUT
#########################################
output "aws_public_subnets_comma_string" {
  description = "value"
  value       = join(",", module.vpc.public_subnet_ids)
}

#########################################
# EKS INFRA OUTPUT
#########################################
output "cluster_id" {
  description = "EKS cluster ID."
  value       = module.eks.cluster_id
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane."
  value       = module.eks.cluster_endpoint
}

output "cluster_security_group_id" {
  description = "Security group ids attached to the cluster control plane."
  value       = module.eks.cluster_security_group_id
}

output "cluster_name" {
  description = "Kubernetes Cluster Name"
  value       = module.eks.cluster_name
}

output "cluster_certificate_authority_data" {
  description = "base64 encoded certificate data required to communicate with your cluster"
  value       = module.eks.cluster_certificate_authority_data
}

#######
# OIDC
#######

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.eks.cluster_oidc_issuer_url
}

output "cluster_oidc_provider" {
  description = "OpenID Connect identity provider without leading http"
  value       = module.eks.cluster_oidc_provider
}

output "cluster_oidc_provider_arn" {
  description = "OpenID Connect identity provider ARN"
  value       = module.eks.cluster_oidc_provider_arn
}

####################
# Cert Manager IRSA
####################
output "cert_manager_role_arn" {
  description = "The ARN of the AWS Role created for cert-manager to use"
  value       = module.cert_manager_irsa_iam_role[0].irsa_role_arn
}

####################
# External DNS IRSA
####################
output "external_dns_role_arn" {
  description = "The ARN of the AWS Role created for external-dns to use"
  value       = module.external_dns_irsa_iam_role[0].irsa_role_arn
}

####################
# Cert Manager IRSA
####################
output "aws_ebs_csi_driver_role_arn" {
  description = "The ARN of the AWS Role created for AWS EBS CSI Driver to use"
  value       = module.ebs_csi_irsa_iam_role[0].irsa_role_arn
}
