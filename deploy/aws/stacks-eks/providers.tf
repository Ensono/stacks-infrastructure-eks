########################################
# Provider to connect to AWS
# https://www.terraform.io/docs/providers/aws/
########################################
provider "aws" {}

provider "helm" {
  kubernetes {
    host                   = module.amido_stacks_infra.cluster_endpoint
    cluster_ca_certificate = base64decode(module.amido_stacks_infra.cluster_certificate_authority_data)
    exec {
      api_version = "client.authentication.k8s.io/v1"
      args        = ["eks", "get-token", "--cluster-name", module.amido_stacks_infra.cluster_name]
      command     = "aws"
    }
  }
}

terraform {
  required_version = ">= 0.14"

  backend "s3" {} # use backend.config for remote backend

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }

    # TODO: Remove me once the ingress has moved out of TF...
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
  }

}
