############################################
# NAMING
############################################

variable "name_company" {
  type    = string
  default = "ensono"
}

variable "name_project" {
  type    = string
  default = "stacks"
}

variable "name_component" {
  type    = string
  default = "compute"
}

variable "name_environment" {
  type    = string
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

  description = "Name of the AWS Region for Deployment."
  type        = string
  default     = "eu-west-2"
}

########################################
# Cluster Configuration
########################################

variable "cluster_version" {

  description = "Cluster Kubernetes Version."
  type        = string
  default     = "1.27"
}

variable "enable_irsa" {

  description = "Switch to enable IRSA."
  type        = bool
  default     = true
}

variable "cluster_endpoint_private_access" {

  description = "Switch to enable private access."
  type        = bool
  default     = false
}

variable "cluster_endpoint_public_access" {

  description = "Switch to enable public access."
  type        = bool
  default     = true
}

variable "eks_desired_nodes" {

  description = "Configure desired no of nodes for the cluster."
  type        = string
  default     = 2
}

variable "eks_node_size" {

  description = "Configure desired spec of nodes for the cluster."
  type        = string
  default     = "t3.small"
}

variable "map_users" {

  default = [{
    userarn  = "arn:aws:iam::640853641954:user/kubeadmin"
    username = "kubeadmin"
    groups   = ["system:masters"]
  }]

  description = "Additional IAM users to add to the aws-auth configmap."

  type = list(object({
    userarn  = string
    username = string
    groups   = list(string)
  }))
}

variable "manage_aws_auth_configmap" {

  description = "Determines whether to manage the aws-auth configmap"
  type        = bool
}

# variable "map_roles" {

#   default     = []
#   description = "Additional IAM roles to add to the aws-auth configmap."
#   type = list(object({
#     rolearn  = string
#     username = string
#     groups   = list(string)
#   }))
# }

########################################
# DNS Configuration
########################################


variable "dns_hostedzone_name" {
  description = "Name of the hosted-zone in Route53."
  type        = string
  default     = "nonprod.aws.stacks.ensono.com"
}



variable "log_retention_period" {
  type        = string
  description = "Specifies the number of days you want to retain log events in the specified log group"
  default     = 180
}
