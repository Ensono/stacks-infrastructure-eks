# Naming convention
module "default_label" {
  source      = "git::https://github.com/cloudposse/terraform-null-label.git?ref=0.24.1"
  namespace   = format("%s-%s", var.name_company, var.name_project)
  environment = var.name_environment
  name        = "${lookup(var.location_name_map, var.region, "eu-west-2")}-${var.name_component}"
  delimiter   = "-"
  tags        = local.default_tags
}
