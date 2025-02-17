############################################
# Naming
############################################

variable "name_company" {
  type = string
}

variable "name_project" {
  type = string
}

variable "name_component" {
  type = string
}

variable "name_environment" {
  type = string
}

variable "region" {
  type        = string
  description = "Name of the AWS Region for Deployment"
}

########################################
# DNS Configuration
########################################
variable "dns_create_hostedzone" {
  type        = bool
  description = "Whether to create the hosted-zone in Route53"
}

variable "dns_hostedzone_name" {
  type        = string
  description = "Name of the hosted-zone in Route53"
}

variable "dns_create_hostedzone_parent_link" {
  type        = bool
  description = "Whether to put the NS records of the hosted-zone into the parent in Route53"
}

variable "dns_parent_hostedzone_name" {
  type        = string
  description = "Name of the Parent hosted-zone in Route53"
}

########################################
# K8s Roles
########################################
variable "k8s_role_file_map" {
  type        = set(string)
  description = "A set of files to read roles from"
}

########################################
# Container Registry
########################################
variable "create_registry" {
  type        = bool
  description = "Create container registry or use a shared container registry created outside the module"
}

variable "container_registry_pull_push_user" {
  type        = bool
  description = "Create a container registry user"
}
