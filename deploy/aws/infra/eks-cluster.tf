module "eks" {
  # TODO: Pin back to a known version after https://github.com/Ensono/stacks-terraform/pull/131/files goes in...
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=feature-cloudwatch-addon"

  region = var.region

  cluster_name                    = module.default_label.id
  cluster_version                 = var.cluster_version
  eks_desired_nodes               = var.eks_desired_nodes
  eks_minimum_nodes               = var.eks_minimum_nodes
  eks_maximum_nodes               = var.eks_maximum_nodes
  eks_node_size                   = var.eks_node_size
  cluster_endpoint_public_access  = var.cluster_endpoint_public_access
  cluster_endpoint_private_access = var.cluster_endpoint_private_access
  cluster_single_az               = var.cluster_single_az

  vpc_id              = module.vpc.id
  vpc_private_subnets = module.vpc.private_subnet_ids

  tags = local.default_tags
}

moved {
  from = module.amido_stacks_infra
  to   = module.eks
}
