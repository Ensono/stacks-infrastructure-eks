module "amido_stacks_infra" {
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=featuer/togglenaming"
  # source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=v1.5.5"

  # Deployment Region
  region = var.region

  # EKS Cluster Configuration
  cluster_name                    = module.default_label.id
  cluster_version                 = var.cluster_version
  eks_desired_nodes               = var.eks_desired_nodes
  eks_minimum_nodes               = var.eks_minimum_nodes
  eks_maximum_nodes               = var.eks_maximum_nodes
  eks_node_size                   = var.eks_node_size
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access

  # Pass Non-default Tag Values to Underlying Modules
  tags = local.default_tags
}
