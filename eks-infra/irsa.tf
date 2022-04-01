data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions = [
      "s3:*",
    ]

    resources = [
      "*",
    ]
  }
}

module "s3_policy_role" {
  source                = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=feature/aws"
  enable_irsa           = true
  namespace             = "default"
  serviceaccount        = "s3-policy"
  create_serviceaccount = true
  cluster               = module.amido_stacks_infra.cluster_name
  issuer_url            = replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")
  aws_account_id        = local.account_id
  policy                = data.aws_iam_policy_document.s3_policy.json
}