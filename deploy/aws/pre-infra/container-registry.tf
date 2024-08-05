# IAM User for pushing
resource "aws_iam_user" "ecr_pull_push" {
  count = var.container_registry_pull_push_user ? 1 : 0
  name  = "${var.name_environment}-ecr-pull-push"
  path  = "/ecr/"
}

resource "aws_iam_access_key" "ecr_pull_push" {
  count = var.container_registry_pull_push_user ? 1 : 0
  user  = aws_iam_user.ecr_pull_push[0].name
}

resource "aws_iam_group" "ecr_pull_push" {
  count = var.container_registry_pull_push_user ? 1 : 0
  name  = "${var.name_environment}-ecr-pull-push"
  path  = "/ecr/"
}

resource "aws_iam_group_membership" "ecr_pull_push" {
  count = var.container_registry_pull_push_user ? 1 : 0
  name  = "ecr-pull-push-group-membership"

  users = [
    aws_iam_user.ecr_pull_push[0].name,
  ]

  group = aws_iam_group.ecr_pull_push[0].name
}

data "aws_iam_policy_document" "ecr_pull_push" {
  count = var.container_registry_pull_push_user ? 1 : 0

  statement {
    effect = "Allow"

    actions = ["ecr:GetAuthorizationToken"]

    resources = ["*"]
  }
}

resource "aws_iam_policy" "ecr_pull_push" {
  count       = var.container_registry_pull_push_user ? 1 : 0
  name        = "${var.name_environment}-ecr-pull-push"
  description = "A policy to allow the `${var.name_environment}-ecr-pull-push` user to auth to the ECR"
  policy      = data.aws_iam_policy_document.ecr_pull_push[0].json
}

resource "aws_iam_group_policy_attachment" "ecr_pull_push" {
  count      = var.container_registry_pull_push_user ? 1 : 0
  group      = aws_iam_group.ecr_pull_push[0].name
  policy_arn = aws_iam_policy.ecr_pull_push[0].arn
}

# TODO: Decide where this goes (ancillary-resources?)
# ECR Set-up
# module "ecr_repositories" {
#   count  = var.container_registry_pull_push_user ? 1 : 0
#   source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/container_registry?ref=v5.0.5"

#   region = var.region

#   repositories = []

#   pull_through_cache_setup = {}

#   pull_accounts = []

#   pull_and_push_accounts = [
#     aws_iam_user.ecr_pull_push[0].arn,
#   ]

#   max_tagged_image_count = 100

#   enable_registry_scanning = false

#   repository_lifecycle_policy = local.repository_lifecycle_policy

#   repository_image_tag_mutability = "IMMUTABLE"
# }
