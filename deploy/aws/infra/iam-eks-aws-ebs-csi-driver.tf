data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "ebs_csi_irsa_iam_role" {
  count = var.aws_ebs_csi_driver_enabled ? 1 : 0

  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v7.0.15"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = var.aws_ebs_csi_driver_namespace
  service_account_name    = var.aws_ebs_csi_driver_service_account_name
  resource_description    = "IAM permissions for Amazon EBS CSI Driver to talk to Amazon EBS to manage volumes"
  policy                  = data.aws_iam_policy.ebs_csi_policy.policy
  policy_prefix           = var.name_environment
}
