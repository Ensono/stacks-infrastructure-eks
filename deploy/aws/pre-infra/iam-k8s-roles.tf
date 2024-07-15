# This is the same across all roles, hence no `for_each`
data "aws_iam_policy_document" "k8s_role" {
  statement {
    effect = "Allow"

    actions = ["eks:DescribeCluster"]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "k8s_role_assume" {
  for_each = local.k8s_role_map

  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = each.value.mapped_users
    }
  }
}

resource "aws_iam_role" "k8s_role" {
  for_each = local.k8s_role_map

  name = "Kubernetes-Cluster-${each.value.role_name}"
  path = "/"

  max_session_duration = each.value.max_session_duration

  assume_role_policy = data.aws_iam_policy_document.k8s_role_assume[each.key].json
}

resource "aws_iam_policy" "k8s_role" {
  for_each = local.k8s_role_map

  name = "${module.default_label.id}-k8s-${lower(each.key)}-policy"

  description = "The policy to allow K8s ${each.value.role_name} to Describe the Cluster"
  policy      = data.aws_iam_policy_document.k8s_role.json
}

resource "aws_iam_role_policy_attachment" "k8s_role" {
  for_each = local.k8s_role_map

  role       = aws_iam_role.k8s_role[each.key].name
  policy_arn = aws_iam_policy.k8s_role[each.key].arn
}
