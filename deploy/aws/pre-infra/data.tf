data "aws_caller_identity" "current" {}

data "aws_route53_zone" "parent" {
  count = var.dns_create_hostedzone && var.dns_create_hostedzone_parent_link ? 1 : 0

  name = var.dns_parent_hostedzone_name
}
