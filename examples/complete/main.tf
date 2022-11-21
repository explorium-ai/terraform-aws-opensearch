provider "aws" {
  region = var.region
}

module "elasticsearch" {
  source = "../../"

  security_groups                = ["sg-0e96016309e807ddd"]
  vpc_id                         = "vpc-04f52d54fe63d1a70"
  subnet_ids                     = ["subnet-0525a2ae23282882d"]
  zone_awareness_enabled         = var.zone_awareness_enabled
  engine_version                 = var.engine_version
  instance_type                  = var.instance_type
  instance_count                 = var.instance_count
  encrypt_at_rest_enabled        = var.encrypt_at_rest_enabled
  dedicated_master_enabled       = var.dedicated_master_enabled
  create_iam_service_linked_role = false
  kibana_subdomain_name          = var.kibana_subdomain_name
  ebs_volume_size                = var.ebs_volume_size
  dns_zone_id                    = var.dns_zone_id
  kibana_hostname_enabled        = var.kibana_hostname_enabled
  domain_hostname_enabled        = var.domain_hostname_enabled

  advanced_options = {
    "rest.action.multi.allow_explicit_index" = "true"
  }

  context = module.this.context
}
