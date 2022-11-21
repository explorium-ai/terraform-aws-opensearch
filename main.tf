# module "user_label" {
#   source  = "cloudposse/label/null"
#   version = "0.25.0"

#   attributes = ["user"]

#   context = module.this.context
# }

# module "kibana_label" {
#   source  = "cloudposse/label/null"
#   version = "0.25.0"

#   attributes = ["kibana"]

#   context = module.this.context
# }

# resource "aws_security_group" "default" {
#   count       = module.this.enabled && var.vpc_enabled ? 1 : 0
#   vpc_id      = var.vpc_id
#   name        = module.this.id
#   description = "Allow inbound traffic from Security Groups and CIDRs. Allow all outbound traffic"
#   tags        = module.this.tags

#   lifecycle {
#     create_before_destroy = true
#   }
# }

# resource "aws_security_group_rule" "ingress_security_groups" {
#   count                    = module.this.enabled && var.vpc_enabled ? length(var.security_groups) : 0
#   description              = "Allow inbound traffic from Security Groups"
#   type                     = "ingress"
#   from_port                = var.ingress_port_range_start
#   to_port                  = var.ingress_port_range_end
#   protocol                 = "tcp"
#   source_security_group_id = var.security_groups[count.index]
#   security_group_id        = join("", aws_security_group.default.*.id)
# }

# resource "aws_security_group_rule" "ingress_cidr_blocks" {
#   count             = module.this.enabled && var.vpc_enabled && length(var.allowed_cidr_blocks) > 0 ? 1 : 0
#   description       = "Allow inbound traffic from CIDR blocks"
#   type              = "ingress"
#   from_port         = var.ingress_port_range_start
#   to_port           = var.ingress_port_range_end
#   protocol          = "tcp"
#   cidr_blocks       = var.allowed_cidr_blocks
#   security_group_id = join("", aws_security_group.default.*.id)
# }

# resource "aws_security_group_rule" "egress" {
#   count             = module.this.enabled && var.vpc_enabled ? 1 : 0
#   description       = "Allow all egress traffic"
#   type              = "egress"
#   from_port         = 0
#   to_port           = 65535
#   protocol          = "tcp"
#   cidr_blocks       = ["0.0.0.0/0"]
#   security_group_id = join("", aws_security_group.default.*.id)
# }

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}


data "aws_route53_zone" "selected" {
  count = var.custom_endpoint_enabled ? 1 : 0
  name         = var.custom_endpoint_domain
  private_zone = var.vpc_enabled
}

resource "aws_route53_record" "custom_endpoint" {
  count = var.custom_endpoint_enabled ? 1 : 0
  zone_id = data.aws_route53_zone.selected[0].zone_id
  name = var.custom_endpoint
  type = "CNAME"
  ttl     = "60"

  records = [
    module.elasticsearch.domain_endpoint
  ]
}

resource "aws_iam_service_linked_role" "example" {
  count            = var.create_iam_service_linked_role ? 1 : 0
  aws_service_name = "opensearchservice.amazonaws.com"
}

resource "aws_cloudwatch_log_group" "example" {
  name = "goga-test-123"
}

resource "aws_cloudwatch_log_resource_policy" "example" {
  policy_name = "goga-test-opensearch"

  policy_document = <<CONFIG
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Action": [
        "logs:PutLogEvents",
        "logs:PutLogEventsBatch",
        "logs:CreateLogStream"
      ],
      "Resource": "arn:aws:logs:*"
    }
  ]
}
CONFIG
}

resource "aws_opensearch_domain" "default" {
  # count                 = module.this.enabled ? 1 : 0
  domain_name           = "gogatest"
  engine_version        = var.engine_version

  access_policies = <<CONFIG
  {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Action": "es:*",
              "Principal": "*",
              "Effect": "Allow",
              "Resource": "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${module.this.id}/*"
          }
      ]
  }
  CONFIG

  advanced_options = var.advanced_options

  advanced_security_options {
    enabled                        = var.advanced_security_options_enabled
    internal_user_database_enabled = var.advanced_security_options_internal_user_database_enabled
    master_user_options {
      master_user_arn      = var.advanced_security_options_master_user_arn
      master_user_name     = var.advanced_security_options_master_user_name
      master_user_password = var.advanced_security_options_master_user_password
    }
  }

  ebs_options {
    ebs_enabled = var.ebs_volume_size > 0 ? true : false
    volume_size = var.ebs_volume_size
    volume_type = var.ebs_volume_type
    iops        = var.ebs_iops
  }

  encrypt_at_rest {
    enabled    = var.encrypt_at_rest_enabled
    kms_key_id = var.encrypt_at_rest_kms_key_id
  }

  domain_endpoint_options {
    enforce_https                   = var.domain_endpoint_options_enforce_https
    tls_security_policy             = var.domain_endpoint_options_tls_security_policy
    custom_endpoint_enabled         = var.custom_endpoint_enabled
    custom_endpoint                 = var.custom_endpoint_enabled ? var.custom_endpoint : null
    custom_endpoint_certificate_arn = var.custom_endpoint_enabled ? var.custom_endpoint_certificate_arn : null
  }

  cluster_config {
    instance_count           = var.instance_count
    instance_type            = var.instance_type
    dedicated_master_enabled = var.dedicated_master_enabled
    dedicated_master_count   = var.dedicated_master_count
    dedicated_master_type    = var.dedicated_master_type
    zone_awareness_enabled   = var.zone_awareness_enabled
    warm_enabled             = var.warm_enabled
    warm_count               = var.warm_enabled ? var.warm_count : null
    warm_type                = var.warm_enabled ? var.warm_type : null

    dynamic "zone_awareness_config" {
      for_each = var.availability_zone_count > 1 && var.zone_awareness_enabled ? [true] : []
      content {
        availability_zone_count = var.availability_zone_count
      }
    }
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption_enabled
  }

  dynamic "vpc_options" {
    for_each = var.vpc_enabled ? [true] : []

    content {
      security_group_ids = [join("", aws_security_group.default.*.id)]
      subnet_ids         = var.subnet_ids
    }
  }

  snapshot_options {
    automated_snapshot_start_hour = var.automated_snapshot_start_hour
  }

  dynamic "cognito_options" {
    for_each = var.cognito_authentication_enabled ? [true] : []
    content {
      enabled          = false
      user_pool_id     = var.cognito_user_pool_id
      identity_pool_id = var.cognito_identity_pool_id
      role_arn         = var.cognito_iam_role_arn
    }
  }

  # log_publishing_options {
  #   enabled                  = var.log_publishing_index_enabled
  #   log_type                 = "INDEX_SLOW_LOGS"
  #   cloudwatch_log_group_arn = var.log_publishing_index_cloudwatch_log_group_arn
  # }

  log_publishing_options {
    enabled                  = var.log_publishing_search_enabled
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
  }

  # log_publishing_options {
  #   enabled                  = var.log_publishing_audit_enabled
  #   log_type                 = "AUDIT_LOGS"
  #   cloudwatch_log_group_arn = var.log_publishing_audit_cloudwatch_log_group_arn
  # }

  log_publishing_options {
    enabled                  = var.log_publishing_application_enabled
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
  }

  tags = module.this.tags

  depends_on = [aws_iam_service_linked_role.example]
}

module "domain_hostname" {
  source  = "cloudposse/route53-cluster-hostname/aws"
  version = "0.12.2"

  enabled  = module.this.enabled && var.domain_hostname_enabled
  dns_name = var.elasticsearch_subdomain_name == "" ? module.this.id : var.elasticsearch_subdomain_name
  ttl      = 60
  zone_id  = var.dns_zone_id
  records  = [join("", aws_opensearch_domain.default.*.endpoint)]

  context = module.this.context
}

module "kibana_hostname" {
  source  = "cloudposse/route53-cluster-hostname/aws"
  version = "0.12.2"

  enabled  = module.this.enabled && var.kibana_hostname_enabled
  dns_name = var.kibana_subdomain_name == "" ? module.kibana_label.id : var.kibana_subdomain_name
  ttl      = 60
  zone_id  = var.dns_zone_id
  # Note: kibana_endpoint is not just a domain name, it includes a path component,
  # and as such is not suitable for a DNS record. The plain endpoint is the
  # hostname portion and should be used for DNS.
  records = [join("", aws_opensearch_domain.default.*.endpoint)]

  context = module.this.context
}
