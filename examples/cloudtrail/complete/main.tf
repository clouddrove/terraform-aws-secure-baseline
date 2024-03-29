## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

locals {
  name = "cloudtrail-testing"
}

#Module      : CLOUDTRAIL
#Description : enables auditing, security monitoring, and operational troubleshooting by tracking user activity and API usage.
module "cloudtrail" {
  source = "../../../modules/cloudtrail"

  name        = local.name
  environment = "security"
  label_order = ["name", "environment"]

  # Cloudtrail S3 Bucket Configuration
  create_bucket           = true
  bucket_versioning       = true
  logging                 = true
  force_destroy           = true
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  # Cloudtrail Configuration
  enabled_cloudtrail    = true
  enable_cloudwatch     = true
  bucket_policy         = true
  is_multi_region_trail = true
  kms_enabled           = true
  enable_logging        = true

  event_ignore_list = jsonencode([
    "^Describe*",
    "^Assume*",
    "^List*",
    "^Get*",
    "^Decrypt*",
    "^Lookup*",
    "^BatchGet*",
    "^CreateLogStream$",
    "^RenewRole$",
    "^REST.GET.OBJECT_LOCK_CONFIGURATION$",
    "TestEventPattern",
    "TestScheduleExpression",
    "CreateNetworkInterface",
    "ValidateTemplate"
  ])
  event_alert_list = jsonencode([
    "DetachRolePolicy",
    "ConsoleLogin"
  ])
  user_ignore_list = jsonencode([
    "^awslambda_*",
    "^aws-batch$",
    "^bamboo*",
    "^i-*",
    "^[0-9]*$",
    "^ecs-service-scheduler$",
    "^AutoScaling$",
    "^AWSCloudFormation$",
    "^CloudTrailBot$",
    "^SLRManagement$"
  ])
  source_list = jsonencode([
    "aws-sdk-go"
  ])

  # Slack Alerts
  slack_webhook = "" # Webhook for the slack notification
  slack_channel = "" # Channel of the Slack where the notification will receive
}