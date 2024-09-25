data "aws_iam_policy_document" "cert_manager" {
  statement {
    effect = "Allow"

    actions = [
      "route53:GetChange",
    ]

    resources = [
      "arn:aws:route53:::change/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "route53:ChangeResourceRecordSets",
      "route53:ListResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "route53:ListHostedZonesByName",
    ]

    resources = [
      "*",
    ]
  }
}

module "cert_manager_irsa_iam_role" {
  count = var.cert_manager_enabled ? 1 : 0

  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v6.0.17"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = var.cert_manager_namespace
  service_account_name    = var.cert_manager_service_account_name
  resource_description    = "cert-manager to update records in Route53 for DNS challenge"
  policy                  = data.aws_iam_policy_document.cert_manager.json
  policy_prefix           = var.name_environment
}
