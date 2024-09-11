# Managed By : CloudDrove
# Description : This Script is used to create CloudTrail.
# Copyright @ CloudDrove. All Right Reserved.

locals {
  bucket_name = coalesce(var.bucket_name, module.s3_logs.id)
  # bucket_id   = coalesce(join("", data.aws_s3_bucket.bucket.*.arn), module.s3_logs.arn)
}

#Module      : Labels
#Description : This terraform module is designed to generate consistent label names and tags
#              for resources. You can use terraform-labels to implement a strict naming
#              convention.
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "1.3.0"

  name        = var.name
  repository  = var.repository
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order
}

###---------------------------------------------------------------------------------------
#Module      : S3 BUCKET
#Description : Terraform module to create default S3 bucket with logging and encryption.
## A public cloud storage resource available in Amazon Web Services (AWS) Simple Storage Service (S3) platform.
###--------------------------------------------------------------------------------------------
locals {
  bucket_environment = coalesce(var.bucket_environment, var.environment)
  create_bucket      = var.create_bucket && var.enabled_cloudtrail
}

module "s3_logs" {
  source  = "clouddrove/s3/aws"
  version = "2.0.0"
  
  enabled                      = var.create_bucket
  name                         = var.name
  s3_name                      = var.bucket_name
  environment                  = local.bucket_environment
  label_order                  = var.label_order
  logging                      = var.logging
  versioning                   = var.bucket_versioning
  acl                          = "log-delivery-write"
  block_public_acls            = var.block_public_acls
  block_public_policy          = var.block_public_policy
  ignore_public_acls           = var.ignore_public_acls
  restrict_public_buckets      = var.restrict_public_buckets
  bucket_policy                = var.bucket_policy && var.create_bucket
  aws_iam_policy_document      = data.aws_iam_policy_document.default.json
  force_destroy                = var.force_destroy
  only_https_traffic           = var.only_https_traffic
}

resource "aws_s3_bucket_policy" "s3_default" {
  count  = var.bucket_policy && !var.create_bucket ? 1 : 0
  bucket = local.bucket_name
  policy = data.aws_iam_policy_document.default.json
}


###---------------------------------------------------------------------------------------
#Resource    : CloudWatch
#Description : Terraform resource to create cloudwatch log with logging and encryption for cloudtrail. ( This role is used by CloudTrail to send logs to CloudWatch. )
## CloudWatch enables you to monitor your complete stack (applications, infrastructure, network, and services).
###--------------------------------------------------------------------------------------------
resource "aws_iam_role" "cloudtrail_cloudwatch_role" {
  count              = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  name               = "${var.name}-${var.iam_role_name}"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume_role.json
  tags               = module.labels.tags
}
resource "aws_iam_role_policy" "cloudwatch_delivery_policy" {
  count  = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  name   = format("%s-cloudwatch-delivery-policy", module.labels.id)
  role   = aws_iam_role.cloudtrail_cloudwatch_role[0].id
  policy = data.aws_iam_policy_document.cloudwatch_delivery_policy[0].json
}
resource "aws_cloudwatch_log_group" "cloudtrail" {
  count             = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  name              = "${var.name}-${var.cloudwatch_log_group_name}"
  retention_in_days = var.log_retention_days
  kms_key_id        = join("", aws_kms_key.cloudtrail.*.arn)
}

resource "aws_iam_policy" "cloudtrail_cloudwatch_logs" {
  count  = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  name   = format("%s-cloudwatch-logs-policy", var.name)
  policy = data.aws_iam_policy_document.cloudtrail_cloudwatch_logs.json
}
resource "aws_iam_policy_attachment" "main" {
  count      = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  name       = format("%s-cloudwatch-logs-policy-attachment", var.name)
  policy_arn = aws_iam_policy.cloudtrail_cloudwatch_logs[0].arn
  roles      = [aws_iam_role.cloudtrail_cloudwatch_role[0].name]
}

## Note: Supports only for single account cloudtrail.
resource "aws_kms_key" "cloudtrail" {
  count                   = var.kms_enabled && var.enabled_cloudtrail ? 1 : 0
  description             = "A KMS key used to encrypt CloudTrail log files stored in S3."
  deletion_window_in_days = var.key_deletion_window_in_days
  enable_key_rotation     = var.enable_key_rotation
  policy                  = data.aws_iam_policy_document.kms.json
  tags                    = module.labels.tags
}


###---------------------------------------------------------------------------------------
#Resource    : CloudTrail
#Description : Terraform module to provision an AWS CloudTrail with encrypted S3 bucket.
## An AWS service that helps you enable operational and risk auditing, governance, and compliance of your AWS account.
###--------------------------------------------------------------------------------------------
resource "aws_cloudtrail" "default" {
  count = var.enabled_cloudtrail == true ? 1 : 0

  name                          = module.labels.id
  enable_logging                = var.enable_logging
  s3_bucket_name                = local.bucket_name
  enable_log_file_validation    = var.enable_log_file_validation
  is_multi_region_trail         = var.is_multi_region_trail
  include_global_service_events = var.include_global_service_events
  cloud_watch_logs_role_arn     = coalesce(var.cloud_watch_logs_role_arn, try(aws_iam_role.cloudtrail_cloudwatch_role[0].arn, ""))
  cloud_watch_logs_group_arn    = coalesce(var.cloud_watch_logs_group_arn, try("${aws_cloudwatch_log_group.cloudtrail[0].arn}:*", ""))
  kms_key_id                    = try(aws_kms_key.cloudtrail[0].arn, null) # aws_kms_key.cloudtrail[0].arn != null ? aws_kms_key.cloudtrail[0].arn : null
  is_organization_trail         = var.is_organization_trail
  tags                          = module.labels.tags
  sns_topic_name                = var.sns_topic_name

  dynamic "event_selector" {
    for_each = var.event_selector
    content {
      include_management_events = lookup(event_selector.value, "include_management_events", null)
      read_write_type           = lookup(event_selector.value, "read_write_type", null)
      exclude_management_event_sources = event_selector.value.exclude_management_event_sources
      dynamic "data_resource" {
        for_each = lookup(event_selector.value, "data_resource", [])
        content {
          type   = data_resource.value.type
          values = data_resource.value.values
        }
      }
    }
  }

  dynamic "insight_selector" {
    for_each = var.insight_selector
    content {
      insight_type = insight_selector.value.insight_type
    }
  }

  lifecycle {
    ignore_changes = [event_selector]
  }

  depends_on = [
    aws_kms_key.cloudtrail,
    module.s3_logs
  ]
}

###---------------------------------------------------------------------------------------
#Resource    : Slack Notification Service
#Description : Terraform module to create Lambda resource on AWS for sending notification when anything done from console in AWS.
## Allows author to deliver notification on slack channels for alerts, warnings and errors.
###--------------------------------------------------------------------------------------------
module "cloudtrail-slack-notification" {
  source  = "clouddrove/cloudtrail-slack-notification/aws"
  version = "1.0.1"

  name        = format("%s-cloudtrail-slack-notification", var.name)
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order
  enabled     = var.slack_webhook != "" && var.enabled_cloudtrail
  bucket_arn  = format("arn:aws:s3:::%s", local.bucket_name)
  bucket_name = local.bucket_name
  variables = {
    slack_webhook     = var.slack_webhook
    slack_channel     = var.slack_channel
    event_ignore_list = var.event_ignore_list
    event_alert_list  = var.event_alert_list
    user_ignore_list  = var.user_ignore_list
    source_list       = var.source_list
  }
}