locals {
  # Each region must have corresponding a shortend name for resource naming purposes
  location_name_map = {
    eu-west-2 = "ew2"
    eu-west-1 = "ew1"
    eu-west-3 = "ew3"
  }

  # This is a map of default tags passed to the provider.
  # This can be extended like adding cost-code or organization name.
  default_tags = {
    Environment = var.name_environment
    Component   = var.name_component
    Project     = var.name_project
    Company     = var.name_company
    Region      = var.region
  }

  # This is used to pass component specific tags.
  # Environment parameter is mandatory as it has been reused in cluster-name, vpc-name and kms key-name
  tags = {
    Environment = var.name_environment
  }

  account_id = data.aws_caller_identity.current.account_id

  # K8s users
  k8s_json_files = [
    for json_file in var.k8s_role_file_map : jsondecode(file(json_file))
  ]

  ## Turn the role map files into a map by using the `role_name` as the map
  ## key. Also this creates a list of mapped users with the role prefix
  ## added, and the `<ACCOUNT_ID>` string replaced with the current AWS
  ## Account ID.
  ## Note this filters out empty lists so TF doesn't try to create empty
  ## resources and error out.
  k8s_role_map = {
    for role_map in local.k8s_json_files : lower(role_map.role_name) => merge(
      role_map,
      {
        mapped_users = [
          for user in role_map.users : "${replace(role_map.role_prefix, "<ACCOUNT_ID>", data.aws_caller_identity.current.account_id)}/${user}"
        ]
      },
    ) if length(role_map.users) > 0
  }
}

data "aws_caller_identity" "current" {}
