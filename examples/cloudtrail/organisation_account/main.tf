## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

module "cloudtrail" {
  source = "../../../modules/cloudtrail"

  name        = "cloudtrail-testing"
  environment = "security"
  label_order = ["name", "environment"]

  enabled_cloudtrail    = true
  bucket_policy         = true
  is_multi_region_trail = true
  kms_enabled           = true
  bucket_versioning     = true
  logging               = true

  is_organization_trail = true

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