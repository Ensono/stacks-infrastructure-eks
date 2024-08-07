########################################
# Provider to connect to AWS
# https://www.terraform.io/docs/providers/aws/
########################################
provider "aws" {
  region = var.region
}

terraform {
  required_version = ">= 1.0"

  backend "s3" {} # use backend.config for remote backend

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

}
