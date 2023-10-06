data "aws_iam_policy_document" "external_dns" {
  statement {
    effect = "Allow"

    actions = [
      "route53:ChangeResourceRecordSets",
    ]

    resources = [
      "arn:aws:route53:::hostedzone/*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
    ]

    resources = [
      "*",
    ]
  }
}

module "external_dns_irsa_iam_role" {
  count = var.external_dns_enabled ? 1 : 0

  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=featuer/togglenaming"
  # source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa?ref=v1.5.5"

  cluster_name            = module.default_label.id
  cluster_oidc_issuer_url = module.amido_stacks_infra.cluster_oidc_issuer_url
  aws_account_id          = local.account_id
  namespace               = var.external_dns_namespace
  service_account_name    = var.external_dns_service_account_name
  resource_description    = "external-dns to list zones and records and update the records"
  policy                  = data.aws_iam_policy_document.external_dns.json
}
