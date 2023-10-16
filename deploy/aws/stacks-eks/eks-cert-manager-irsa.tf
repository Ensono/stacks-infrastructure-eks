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
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=featuer/togglenaming"
  # source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v1.5.5"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.amido_stacks_infra.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = "cert-manager"
  service_account_name    = "cert-manager-sa"
  resource_description    = "cert-manager to update records in Route53 for DNS challenge"
  policy                  = data.aws_iam_policy_document.cert_manager.json
}
