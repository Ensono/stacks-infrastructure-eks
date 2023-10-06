############################################
# NAMING
############################################

variable "name_company" {
  type = string

  default = "ensono"
}

variable "name_project" {
  type = string

  default = "stacks"
}

variable "name_component" {
  type = string

  default = "eks"
}

variable "name_environment" {
  type = string

  default = "nonprod"
}

# Each region must have corresponding a shortend name for resource naming purposes
variable "location_name_map" {
  type = map(string)

  default = {
    eu-west-2 = "ew2"
    eu-west-1 = "ew1"
    eu-west-3 = "ew3"
  }
}

variable "region" {
  type        = string
  description = "Name of the AWS Region for Deployment."

  default = "eu-west-2"
}

########################################
# Cluster Configuration
########################################

variable "cluster_version" {
  type        = string
  description = "Cluster Kubernetes Version."

  default = "1.27"
}

variable "enable_irsa" {
  type        = bool
  description = "Switch to enable IRSA."

  default = true
}

variable "cluster_endpoint_private_access" {
  type        = bool
  description = "Switch to enable private access."

  default = false
}

variable "cluster_endpoint_public_access" {
  type        = bool
  description = "Switch to enable public access."

  default = true
}

variable "eks_minimum_nodes" {
  type        = string
  description = "The minimum number of nodes in the cluster"

  default = 1
}

variable "eks_desired_nodes" {
  type        = string
  description = "The initial starting number of nodes, ignored after first apply"

  default = 2
}

variable "eks_maximum_nodes" {
  type        = string
  description = "The maximum number of nodes in the cluster"

  default = 3
}

variable "eks_node_size" {
  type        = string
  description = "Configure desired spec of nodes for the cluster."

  default = "t3.small"
}

########################################
# DNS Configuration
########################################

variable "dns_hostedzone_name" {
  type        = string
  description = "Name of the hosted-zone in Route53."

  default = "nonprod.aws.stacks.ensono.com"
}

variable "log_retention_period" {
  type        = string
  description = "Specifies the number of days you want to retain log events in the specified log group"

  default = 180
}

##########
# Ingress
##########
variable "aws_lb_controller_enabled" {
  type        = bool
  description = "Whether to enable AWS Load Balancer Controller or not"
}

variable "aws_lb_controller_service_account_name" {
  type        = string
  description = "The Kubernetes Service Account name for AWS Load Balancer Controller"
}

variable "aws_lb_controller_namespace" {
  type        = string
  description = "The Namespace that AWS Load Balancer Controller will be deployed to"
}

###############
# External DNS
###############
variable "external_dns_enabled" {
  type        = bool
  description = "Whether to enable External DNS or not"
}

variable "external_dns_service_account_name" {
  type        = string
  description = "The Kubernetes Service Account name for External DNS"
}

variable "external_dns_namespace" {
  type        = string
  description = "The Namespace that External DNS will be deployed to"
}
