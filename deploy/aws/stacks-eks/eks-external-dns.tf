# Trust policy for aws external-dns
data "aws_iam_policy_document" "external_dns_assume_role_policy" {
  statement {

    actions = [
      "sts:AssumeRoleWithWebIdentity",
    ]

    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::${local.account_id}:oidc-provider/${replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")}:sub"
      values   = ["system:serviceaccount:${var.external_dns_namespace}:${var.external_dns_service_account_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "${replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

# IAM Role for external DNS
resource "aws_iam_role" "external_dns" {
  name                  = "${module.amido_stacks_infra.cluster_name}-role-dns"
  assume_role_policy    = data.aws_iam_policy_document.external_dns_assume_role_policy.json
  force_detach_policies = true
  tags                  = local.default_tags
}

# IAM policy for aws-alb-ingress-controller role
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

resource "aws_iam_policy" "external_dns" {
  name        = "rolepolicy-external-dns"
  path        = "/${module.amido_stacks_infra.cluster_name}/"
  description = "Permissions for external-dns to list zones and records and update the records"

  policy = data.aws_iam_policy_document.external_dns.json
}

resource "aws_iam_role_policy_attachment" "external_dns" {
  role       = aws_iam_role.external_dns.id
  policy_arn = aws_iam_policy.external_dns.arn
}
