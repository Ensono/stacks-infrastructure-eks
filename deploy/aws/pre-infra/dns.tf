resource "aws_route53_zone" "environment" {
  count = var.dns_create_hostedzone ? 1 : 0

  name = var.dns_hostedzone_name
}

resource "aws_route53_record" "environment_parent_link" {
  count = var.dns_create_hostedzone && var.dns_create_hostedzone_parent_link ? 1 : 0

  zone_id = data.aws_route53_zone.parent.0.zone_id
  name    = var.dns_hostedzone_name

  type = "NS"
  ttl  = 300

  records = aws_route53_zone.environment.0.name_servers
}
