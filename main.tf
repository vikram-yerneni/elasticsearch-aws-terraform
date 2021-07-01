# The Security Group will help us to configure/control traffic into and out to Elasticsearch Domain including Kibana Control Access
resource "aws_security_group" "default" {
  vpc_id      = var.vpc_id
  name        = var.aws_security_group #need help with this setup too
  description = "Allow inbound traffic from Security Groups and CIDRs. Allow all outbound traffic"
}

# The Ingress rule allows us to add any specific security groups that needs to be allowed traffic from
resource "aws_security_group_rule" "ingress_security_groups" {
  count                    = length(var.security_groups)
  description              = "Allow inbound traffic from Security Groups"
  type                     = "ingress"
  from_port                = var.ingress_port_range_start
  to_port                  = var.ingress_port_range_end
  protocol                 = "tcp"
  source_security_group_id = var.security_groups[count.index]
  security_group_id        = join("", aws_security_group.default.*.id)
}

# The Ingress rule allows us to add any specific IP Ranges/Ports or CIDR Blocks that needs to be allowed traffic from
resource "aws_security_group_rule" "ingress_cidr_blocks" {
  description       = "Allow inbound traffic from CIDR blocks"
  type              = "ingress"
  from_port         = var.ingress_port_range_start
  to_port           = var.ingress_port_range_end
  protocol          = "tcp"
  cidr_blocks       = var.allowed_cidr_blocks
  security_group_id = join("", aws_security_group.default.*.id)
}

# The Ingress rule allows us to add any specific IP/Port that needs to be allowed traffic from elasticsearch domian
resource "aws_security_group_rule" "egress" {
  description       = "Allow all egress traffic"
  type              = "egress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = join("", aws_security_group.default.*.id)
}

# This rule is for utilizing the existing elasticsearch role for creating the ES Domain
resource "aws_iam_service_linked_role" "default" {
  count            = var.create_iam_service_linked_role ? 1 : 0
  aws_service_name = "es.amazonaws.com"
  description      = "AWSServiceRoleForAmazonElasticsearchService Service-Linked Role"
}

#The primary configuration for configuring elasticsearch domain
resource "aws_elasticsearch_domain" "elasticsearch_domain" {
  domain_name           = var.elasticsearch_domain_name
  elasticsearch_version = var.elasticsearch_version
  advanced_options      = var.advanced_options

  advanced_security_options {
    enabled                        = var.advanced_security_options_enabled
    internal_user_database_enabled = var.advanced_security_options_internal_user_database_enabled
    # The "master_user" will have full control over elasticsearch domain (like on all indexes & Kibana)
    # Ref1: https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/fgac.html#fgac-concepts
    # Ref2: https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#master_user_arn
    master_user_options {
      master_user_arn      = var.advanced_security_options_master_user_arn
      master_user_name     = var.advanced_security_options_master_user_name
      master_user_password = var.advanced_security_options_master_user_password
    }
  }

  # In SSI Module, use {storage_type = io1} & {iops = 3000} for production
  ebs_options {
    ebs_enabled = true
    volume_size = var.ebs_volume_size
    volume_type = var.ebs_volume_type
    iops        = var.ebs_iops
  }

  encrypt_at_rest {
    enabled = var.encrypt_at_rest_enabled
    #    kms_key_id = var.encrypt_at_rest_kms_key_id
  }

  domain_endpoint_options {
    enforce_https           = var.domain_endpoint_options_enforce_https
    tls_security_policy     = var.domain_endpoint_options_tls_security_policy
    custom_endpoint_enabled = false
    #    custom_endpoint                 = var.custom_endpoint_enabled ? var.custom_endpoint : null
    #    custom_endpoint_certificate_arn = var.custom_endpoint_enabled ? var.custom_endpoint_certificate_arn : null
  }

  # We need to set the var.production_mode for the 3 Availability Zones, 2 replicas, 5 primary shards & 5 data nodes - Need to dig in more here
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
      for_each = var.availability_zone_count > 1 ? [true] : []
      content {
        availability_zone_count = var.availability_zone_count
      }
    }
  }

  node_to_node_encryption {
    enabled = var.node_to_node_encryption_enabled
  }

  # We need to add existing subnet & security groups for setting up the VPC for elasticsearch
  dynamic "vpc_options" {
    for_each = var.vpc_enabled ? [true] : []
    content {
      security_group_ids = [join("", aws_security_group.default.*.id)]
      subnet_ids         = var.subnet_ids
    }
  }

  # Need to enable only on production mode - Will setup
  snapshot_options {
    automated_snapshot_start_hour = var.automated_snapshot_start_hour
  }

  log_publishing_options {
    enabled                  = var.log_publishing_index_enabled
    log_type                 = "INDEX_SLOW_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_index_cloudwatch_log_group_arn
  }

  log_publishing_options {
    enabled                  = var.log_publishing_search_enabled
    log_type                 = "SEARCH_SLOW_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_search_cloudwatch_log_group_arn
  }

  log_publishing_options {
    enabled                  = var.log_publishing_audit_enabled
    log_type                 = "AUDIT_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_audit_cloudwatch_log_group_arn
  }

  log_publishing_options {
    enabled                  = var.log_publishing_application_enabled
    log_type                 = "ES_APPLICATION_LOGS"
    cloudwatch_log_group_arn = var.log_publishing_application_cloudwatch_log_group_arn
  }
  depends_on = [aws_iam_service_linked_role.default]
}

# This is to set Access Policy for Elasticsearch Domain - Controls Authorization
data "aws_iam_policy_document" "default" {
  statement {
    effect = "Allow"
    resources = [
      join("", aws_elasticsearch_domain.elasticsearch_domain.*.arn),
      "${join("", aws_elasticsearch_domain.elasticsearch_domain.*.arn)}/*"
    ]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "es:*"
    ]
  }
}

resource "aws_elasticsearch_domain_policy" "elasticsearch_domain_policy" {
  domain_name     = var.elasticsearch_domain_name
  access_policies = join("", data.aws_iam_policy_document.default.*.json)
}

# Route53 Entry for the Elasticsearch Domain
data "aws_route53_zone" "org_private_dns_zone" {
  name         = "org-private."
  private_zone = true
  vpc_id       = var.vpc_id
}

resource "aws_route53_record" "elastisearch_dns" {
  zone_id = local.dns_zone_id
  name    = local.dns_address
  type    = "CNAME"
  ttl     = 300
  records = [aws_elasticsearch_domain.elasticsearch_domain.endpoint]
}

locals {
  dns_address = "elasticsearch.${data.aws_route53_zone.org_private_dns_zone.name}"
  dns_zone_id = data.aws_route53_zone.org_private_dns_zone.zone_id
}
