####################
# Container Insights
####################

module "container_insights" {
  source  = "gooygeek/container-insights/helm"
  version = "1.0.0"

  aws_region            = var.region
  iam_role_name         = "${module.amido_stacks_infra.cluster_name}-role-ci"
  eks_cluster_name      = module.amido_stacks_infra.cluster_name
  eks_oidc_provider_url = module.amido_stacks_infra.cluster_oidc_issuer_url
  eks_oidc_provider_arn = "arn:aws:iam::${local.account_id}:oidc-provider/${replace(module.amido_stacks_infra.cluster_oidc_issuer_url, "https://", "")}"
}

#######################
# CloudWatch-Log Group
#######################

resource "aws_cloudwatch_log_group" "amido_stacks_eks" {
  name              = "${module.amido_stacks_infra.cluster_name}-logs"
  retention_in_days = var.log_retention_period
}
