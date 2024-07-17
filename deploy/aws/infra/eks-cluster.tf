data "aws_iam_policy" "cloudwatch_agent_server_policy" {
  name = "CloudWatchAgentServerPolicy"
}

module "amido_stacks_infra" {
  # TODO: Pin back to a known version after https://github.com/Ensono/stacks-terraform/pull/132/files goes in...
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks?ref=vfeat/eks-extra-iam-policy"

  # Deployment Region
  region = var.region

  # EKS Cluster Configuration
  cluster_name                            = module.default_label.id
  cluster_version                         = var.cluster_version
  eks_desired_nodes                       = var.eks_desired_nodes
  eks_minimum_nodes                       = var.eks_minimum_nodes
  eks_maximum_nodes                       = var.eks_maximum_nodes
  eks_node_size                           = var.eks_node_size
  cluster_endpoint_public_access          = var.cluster_endpoint_public_access
  cluster_endpoint_private_access         = var.cluster_endpoint_private_access
  cluster_single_az                       = var.cluster_single_az
  cluster_iam_role_additional_policies    = {
    cloudwatch_agent_server_policy = data.aws_iam_policy.cloudwatch_agent_server_policy.arn
  }

  vpc_id              = module.vpc.id
  vpc_private_subnets = module.vpc.private_subnet_ids

  tags = local.default_tags
}
