data "aws_iam_policy_document" "external_dns" {
  statement {
    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]

    effect = "Allow"
  }

  statement {
    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:ListTagsForResource",
    ]

    resources = [
      "*",
    ]

    effect = "Allow"
  }
}

module "external_dns_irsa_iam_role" {
  count = var.external_dns_enabled ? 1 : 0

  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v6.0.15"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.eks.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = var.external_dns_namespace
  service_account_name    = var.external_dns_service_account_name
  resource_description    = "external-dns to add records in Route53 for services"
  policy                  = data.aws_iam_policy_document.external_dns.json
  policy_prefix           = var.name_environment
}
