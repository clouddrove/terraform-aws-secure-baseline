provider "aws" {
  region = "us-east-1"
}

locals {
  name = "cloudtrail-testing"
}

module "cloudtrail" {
  source = "../../../modules/cloudtrail"

  name        = local.name
  environment = "security"
  label_order = ["name", "environment"]

  create_bucket     = true
  bucket_versioning = true
  enable_logging    = true
  force_destroy     = true

  enabled_cloudtrail    = true
  enable_cloudwatch     = true
  bucket_policy         = true
  is_multi_region_trail = true
  kms_enabled           = true

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