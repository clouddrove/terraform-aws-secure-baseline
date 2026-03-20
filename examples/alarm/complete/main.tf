## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.
provider "aws" {
  region = "us-east-1"
}

#Module      : ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
module "alarm" {
  source      = "../../../modules/alarm"
  name        = "alarm"
  environment = "test"
  label_order = ["name", "environment"]

  enabled                    = true
  unauthorized_api_calls     = true
  no_mfa_console_signin      = true
  root_usage                 = true
  iam_changes                = true
  cloudtrail_cfg_changes     = true
  console_signin_failures    = true
  disable_or_delete_cmk      = true
  s3_bucket_policy_changes   = true
  security_group_changes     = true
  nacl_changes               = true
  network_gw_changes         = true
  route_table_changes        = true
  vpc_changes                = true
  alarm_namespace            = "Alert_Alarm"
  aws_config_changes_enabled = true

  variables = {
    SLACK_WEBHOOK = "" # Webhook for the slack notification
    SLACK_CHANNEL = "" # Channel of the Slack where the notification will receive
  }
}
