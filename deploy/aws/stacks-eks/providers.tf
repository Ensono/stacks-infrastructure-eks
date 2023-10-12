########################################
# Provider to connect to AWS
# https://www.terraform.io/docs/providers/aws/
########################################
provider "aws" {
  region = var.region
}

provider "kubernetes" {

  host                     = module.amido_stacks_infra.cluster_endpoint
  cluster_ca_certificate   = base64decode(module.amido_stacks_infra.cluster_certificate_authority_data)
  config_context_auth_info = "aws"

  exec {
    api_version = "client.authentication.k8s.io/v1"
    command     = "aws"
    args        = ["eks", "get-token", "--cluster-name", module.amido_stacks_infra.cluster_name]
  }

}

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
  required_version = ">= 1.0"

  //backend "s3" {} # use backend.config for remote backend

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

}
