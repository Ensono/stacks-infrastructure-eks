########################################
# Amido Stacks Infra Configuration
########################################

# Naming convention
module "default_label" {
  source      = "git::https://github.com/cloudposse/terraform-null-label.git?ref=0.24.1"
  namespace   = format("%s-%s", var.name_company, var.name_project)
  environment = var.name_environment
  name        = "${lookup(var.location_name_map, var.region, "eu-west-2")}-${var.name_component}"
  delimiter   = "-"
  tags        = local.tags
}


module "amido_stacks_infra" {
  source = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=featuer/togglenaming"
  # source = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=v1.5.5"

  # Deployment Region
  region = var.region

  # EKS Cluster Configuration
  cluster_name                    = module.default_label.id
  cluster_version                 = var.cluster_version
  eks_desired_nodes               = var.eks_desired_nodes
  enable_irsa                     = var.enable_irsa
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access

  # Route-53 Zone Configuration
  enable_zone  = var.enable_zone
  public_zones = var.public_zones


  # Provides EKS API Access to Additional IAM Users and Roles, default Admin access is provided only to the cluster creator identity
  map_roles = var.map_roles
  map_users = var.map_users

  # Pass Non-default Tag Values to Underlying Modules
  tags = local.tags
}
