variable "region" {

  description = "Name of the AWS Region for Deployment."
  type        = string
}

variable "cluster_name" {

  description = "Name of the cluster."
  type        = string
}

variable "cluster_version" {

  description = "Cluster Kubernetes Version."
  type        = string
}

variable "enable_irsa" {

  description = "Switch to ebale IRSA."
  type        = bool
}

variable "cluster_endpoint_private_access" {

  description = "Switch to enable private access."
  type        = bool
}

variable "cluster_endpoint_public_access" {

  description = "Switch to enable public access."
  type        = bool
}

variable "eks_desired_nodes" {

  description = "Configure desired no of nodes for the cluster."
  type        = string
}

variable "map_users" {

  default     = []
  description = "Additional IAM users to add to the aws-auth configmap."
  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
}

variable "map_roles" {

  default     = []
  description = "Additional IAM roles to add to the aws-auth configmap."
  type = list(object({
    rolearn  = string
    username = string
    groups   = list(string)
  }))
}

variable "env" {

  default     = "Test"
  description = "Name of the deployment environment."
  type        = string
}

variable "app_name" {

  description = "Friendly-Name of the Application/Project used in tags."
  type        = string
}

variable "owner" {

  description = "Owner of the Application/Project used in tags."
  type        = string
}


variable "dns_hostedzone_name" {

  description = "Name of the hosted-zone in Route53."
  type        = string
}
variable "enable_zone" {
  description = "Conditionally create route53 zones."
  type        = bool
}

variable "public_zones" {
  type        = map(any)
  description = "Map of Route53 zone parameters."
}

variable "log_retention_period" {
  type        = string
  description = "Specifies the number of days you want to retain log events in the specified log group"
  default     = 180
}
