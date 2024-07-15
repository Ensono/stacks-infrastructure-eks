# Create a VPC for our usage
module "vpc" {
  source = "git::https://github.com/Ensono/stacks-terraform//aws/modules/infrastructure_modules/vpc?ref=v5.0.5"

  region = var.region

  vpc_cidr = var.vpc_cidr
  vpc_name = module.default_label.id

  firewall_enabled                = var.firewall_enabled
  firewall_allowed_domain_targets = var.firewall_allowed_domain_targets
  create_tls_alert_rule           = var.firewall_create_tls_alert_rule
  firewall_deletion_protection    = false

  vpc_nat_gateway_per_az = var.vpc_nat_gateway_per_az

  tags = merge(
    local.default_tags,
    {
      Name        = module.default_label.id
      Description = "VPC"
    }
  )
}
