data "aws_iam_policy" "ebs_csi_policy" {
  arn = "arn:aws:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"
}

module "ebs_csi_irsa_iam_role" {
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=featuer/togglenaming"
  # source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v1.5.5"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.amido_stacks_infra.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = "kube-system"
  service_account_name    = "ebs-csi-controller-sa"
  resource_description    = "IAM permissions to talk to Amazon EBS to manage the volume"
  policy                  = data.aws_iam_policy.ebs_csi_policy.policy
}
