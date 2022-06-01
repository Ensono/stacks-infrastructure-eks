data "aws_iam_policy_document" "stacks_dotnet" {
  statement {

    sid = "S3FullAccessForStacksDotNetApp"

    effect = "Allow"

    actions = ["s3:*"]

    resources = ["*"]
  }

  statement {

    sid = "DynamoDBFullAccessForStacksDotNetApp"

    effect = "Allow"

    actions = [
      "dynamodb:*"
    ]

    resources = ["*"]
  }

  statement {

    sid = "SQSFullAccessForStacksDotnetApp"

    effect = "Allow"

    actions = [
      "sqs:*"
    ]

    resources = ["*"]
  }
  statement {

    sid = "SNSFullAccessForStacksDotnetApp"

    effect = "Allow"

    actions = [
      "sns:*"
    ]

    resources = ["*"]
  }
}

data "aws_iam_policy_document" "s3" {
  statement {
    sid = "S3FullAccessForStacksDotnetApp"

    effect = "Allow"

    actions = [
      "s3:*"
    ]

    resources = [
      "*"
    ]
  }
}


module "s3_irsa" {

  source                = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa"
  count                 = var.stacks_dotnet_irsa["create"] ? 1 : 0
  
  enable_irsa           = var.s3_irsa["create"]
  namespace             = var.s3_irsa["namespace"]
  serviceaccount        = var.s3_irsa["service-account-name"]
  create_serviceaccount = true
  cluster               = module.amido_stacks_infra.cluster_name
  issuer_url            = replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")
  aws_account_id        = local.account_id
  policy                = data.aws_iam_policy_document.s3.json
}

module "stacks_dotnet_irsa" {
  

  source                = "git::https://github.com/amido/stacks-terraform//aws/modules/infrastructure_modules/eks_irsa"
  count                 = var.stacks_dotnet_irsa["create"] ? 1 : 0  
  
  enable_irsa           = var.stacks_dotnet_irsa["create"]
  namespace             = var.stacks_dotnet_irsa["namespace"]
  serviceaccount        = var.stacks_dotnet_irsa["service-account-name"]
  create_serviceaccount = true
  cluster               = module.amido_stacks_infra.cluster_name
  issuer_url            = replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")
  aws_account_id        = local.account_id
  policy                = data.aws_iam_policy_document.stacks_dotnet.json
}
