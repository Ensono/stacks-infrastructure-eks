########################################
# NAMING
########################################

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
# VPC Configuration
########################################
variable "vpc_cidr" {
  type        = string
  description = "The VPC CIDR"
}

variable "vpc_nat_gateway_per_az" {
  type        = bool
  description = "Whether to create a NAT Gateway per-AZ or a single one"
}

########################################
# Firewall Configuration
########################################

variable "firewall_enabled" {
  type        = bool
  description = "Whether to create the Fireall and its subnets or not"
}

variable "firewall_allowed_domain_targets" {
  type        = list(string)
  description = "The list of allowed domains which can make it through the firewall, e.g. '.foo.com'"
}

variable "firewall_create_tls_alert_rule" {
  type        = bool
  description = "This variable toggles creation of TLS Alert firewall rules"
}


########################################
# Cluster Configuration
########################################

variable "cluster_version" {
  type        = string
  description = "Cluster Kubernetes Version"
}

variable "cluster_single_az" {
  type        = bool
  description = "Switch to only deploy cluster to a single AZ"
}

variable "cluster_endpoint_private_access" {
  type        = bool
  description = "Switch to enable private access"
}

variable "cluster_endpoint_public_access" {
  type        = bool
  description = "Switch to enable public access"
}

variable "cluster_enable_container_insights" {
  type        = bool
  description = "Whether to install the the Amazon CloudWatch Observability addon to the EKS cluster for Metrics and Application Log Collection"
}

variable "eks_minimum_nodes" {
  type        = string
  description = "The minimum number of nodes in the cluster"
}

variable "eks_desired_nodes" {
  type        = string
  description = "The initial starting number of nodes, ignored after first apply"
}

variable "eks_maximum_nodes" {
  type        = string
  description = "The maximum number of nodes in the cluster"
}

variable "eks_node_size" {
  type        = string
  description = "Configure desired spec of nodes for the cluster"
}

########################################
# Cert Manager IAM IRSA
########################################

variable "cert_manager_enabled" {
  type        = bool
  description = "Whether to enable Cert Manager or not"
}

variable "cert_manager_service_account_name" {
  type        = string
  description = "The Kubernetes Service Account name for Cert Manager"
}

variable "cert_manager_namespace" {
  type        = string
  description = "The Namespace that Cert Manager will be deployed to"
}

########################################
# External DNS IAM IRSA
########################################

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
