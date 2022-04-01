########################################
# Amido Stacks Infra Configuration
########################################

module "amido_stacks_infra" {
  source = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=feature/aws"

  # Deployment Region
  region = var.region

  # EKS Cluster Configuration
  cluster_name                    = var.cluster_name
  cluster_version                 = var.cluster_version
  eks_desired_nodes               = var.eks_desired_nodes
  enable_irsa                     = var.enable_irsa
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access

  # Provides EKS API Access to Additional IAM Users and Roles, default Admin access is provided only to the cluster creator identity
  map_roles = var.map_roles
  map_users = var.map_users

  # Pass Default Tag Values to Underlying Modules
  tags = local.tags
}