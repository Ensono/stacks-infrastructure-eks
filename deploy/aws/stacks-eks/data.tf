locals {
  # This is a map of default tags passed to the provider.
  # This can be extended like adding cost-code or organization name.
  default_tags = {
    Environment = var.env
    Application = var.app_name
    Owner       = var.owner
  }

  # This is used to pass component specific tags.
  # Environment parameter is mandatory as it has been reused in cluster-name, vpc-name and kms key-name,
  # If not supplied it will fallback to "Test" as default environment value.
  tags = {
    Environment = var.env
  }

  account_id = data.aws_caller_identity.current.account_id
}

data "aws_caller_identity" "current" {}