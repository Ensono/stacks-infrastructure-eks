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
      values   = ["system:serviceaccount:kube-system:external-dns"]
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
  name        = "${module.amido_stacks_infra.cluster_name}-rolepolicy-external-dns"
  path        = "/"
  description = "Permissions for external-dns to list zones and records and update the records"

  policy = data.aws_iam_policy_document.external_dns.json
}

resource "aws_iam_role_policy_attachment" "external_dns" {
  role       = aws_iam_role.external_dns.id
  policy_arn = aws_iam_policy.external_dns.arn
}

# Kubernetes Objects: Service Account, Cluster Role and Cluster Role Binding

# resource "kubernetes_service_account" "external_dns" {
#   depends_on = [module.amido_stacks_infra]

#   automount_service_account_token = true

#   metadata {
#     name      = "external-dns"
#     namespace = "kube-system"
#     annotations = {
#       "eks.amazonaws.com/role-arn" = aws_iam_role.external_dns.arn
#     }
#     labels = {
#       "app.kubernetes.io/name" = "${module.amido_stacks_infra.cluster_name}-sa-dns"
#     }
#   }
# }

# resource "kubernetes_cluster_role" "external_dns" {
#   depends_on = [module.amido_stacks_infra]

#   metadata {
#     name = "${module.amido_stacks_infra.cluster_name}-role-dns"
#     labels = {
#       "app.kubernetes.io/name" = "${module.amido_stacks_infra.cluster_name}-role-dns"
#     }
#   }

#   rule {
#     api_groups = [""]

#     resources = [
#       "services",
#       "endpoints",
#       "pods"
#     ]

#     verbs = [
#       "get",
#       "list",
#       "watch"
#     ]
#   }

#   rule {
#     api_groups = [
#       "networking.k8s.io",
#       "extensions"
#     ]

#     resources = [
#       "ingresses"
#     ]

#     verbs = [
#       "get",
#       "list",
#       "watch"
#     ]
#   }

#   rule {
#     api_groups = [""]

#     resources = [
#       "nodes"
#     ]

#     verbs = [
#       "list",
#       "watch"
#     ]
#   }
# }

# resource "kubernetes_cluster_role_binding" "external_dns" {
#   depends_on = [module.amido_stacks_infra]

#   metadata {
#     name = "${module.amido_stacks_infra.cluster_name}-rolebind-dns"
#     labels = {
#       "app.kubernetes.io/name" = "${module.amido_stacks_infra.cluster_name}-rolebind-dns"
#     }
#   }

#   role_ref {
#     api_group = "rbac.authorization.k8s.io"
#     kind      = "ClusterRole"
#     name      = kubernetes_cluster_role.external_dns.metadata[0].name
#   }

#   subject {
#     api_group = ""
#     kind      = "ServiceAccount"
#     name      = kubernetes_service_account.external_dns.metadata[0].name
#     namespace = kubernetes_service_account.external_dns.metadata[0].namespace
#   }
# }


# resource "kubernetes_deployment" "external_dns" {
#   depends_on = [module.amido_stacks_infra]

#   metadata {
#     name      = "${module.amido_stacks_infra.cluster_name}-kube-dns"
#     namespace = "kube-system"
#   }

#   spec {
#     selector {
#       match_labels = {
#         app = "external-dns"
#       }
#     }

#     template {
#       metadata {
#         labels = {
#           app = "external-dns"
#         }
#       }

#       spec {
#         container {
#           name  = "external-dns"
#           image = "k8s.gcr.io/external-dns/external-dns:v0.7.6"
#           args = ["--source=service",
#             "--source=ingress",
#             "--domain-filter=${var.dns_hostedzone_name}", # "example.com"
#             "--provider=aws",
#             "--aws-zone-type=public",
#             "--aws-prefer-cname",
#             "--registry=txt",
#             "--txt-prefix=prefix",
#             "--policy=sync",
#             "--txt-owner-id=${module.amido_stacks_infra.cluster_name}-kube-dns"
#           ]
#         }
#         service_account_name = kubernetes_service_account.external_dns.metadata[0].name

#         security_context {
#           fs_group = 65534
#         }
#       }
#     }

#     strategy {
#       type = "Recreate"
#     }
#   }
# }
