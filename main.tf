
#Module      : CLOUDTRAIL
#Description : Terraform module to provision an AWS CloudTrail with encrypted S3 bucket.
#              This bucket is used to store CloudTrail logs.
module "cloudtrail" {
  source                            = "git::https://github.com/clouddrove/terraform-aws-cloudtrail-baseline.git?ref=tags/0.12.6"
  name                              = "trails"
  application                       = var.application
  environment                       = var.environment
  label_order                       = var.label_order
  enabled                           = var.enabled && var.cloudtrail_enabled
  iam_role_name                     = "CloudTrail-CloudWatch-Delivery-Role"
  iam_role_policy_name              = "CloudTrail-CloudWatch-Delivery-Policy"
  account_type                      = "individual"
  key_deletion_window_in_days       = var.key_deletion_window_in_days
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  cloudwatch_logs_group_name        = var.cloudwatch_logs_group_name
  EVENT_IGNORE_LIST                 = jsonencode(["^Describe*", "^Assume*", "^List*", "^Get*", "^Decrypt*", "^Lookup*", "^BatchGet*", "^CreateLogStream$", "^RenewRole$", "^REST.GET.OBJECT_LOCK_CONFIGURATION$", "TestEventPattern", "TestScheduleExpression", "CreateNetworkInterface", "ValidateTemplate"])
  EVENT_ALERT_LIST                  = jsonencode(["DetachRolePolicy", "ConsoleLogin"])
  USER_IGNORE_LIST                  = jsonencode(["^awslambda_*", "^aws-batch$", "^bamboo*", "^i-*", "^[0-9]*$", "^ecs-service-scheduler$", "^AutoScaling$", "^AWSCloudFormation$", "^CloudTrailBot$", "^SLRManagement$"])
  SOURCE_LIST                       = jsonencode(["aws-sdk-go"])
  s3_bucket_name                    = var.s3_bucket_name
  slack_webhook                     = var.slack_webhook
  slack_channel                     = var.slack_channel
  s3_policy                         = var.s3_policy
}

#Module      : ALARM BASELINE
#Description : Provides a CloudWatch Metric Alarm resource.
module "alarm_baseline" {
  source      = "git::https://github.com/clouddrove/terraform-aws-alarm-baseline.git?ref=tags/0.12.1"
  name        = "alarm"
  application = var.application
  environment = var.environment
  label_order = var.label_order

  enabled                   = var.enabled && var.alarm_enabled
  alarm_namespace           = var.alarm_namespace
  cloudtrail_log_group_name = module.cloudtrail.log_group_name
  variables = {
    SLACK_WEBHOOK = var.slack_webhook
    SLACK_CHANNEL = var.slack_channel
  }
}

#Module      : CONFIG BASELINE
#Description : Manages status (recording / stopped) of an AWS Config Configuration Recorder.
module "config-baseline" {
  source                = "git::https://github.com/clouddrove/terraform-aws-config-baseline.git?ref=tags/0.12.1"
  name                  = "config"
  application           = var.application
  environment           = var.environment
  label_order           = var.label_order
  enabled               = var.enabled && var.config_enabled
  config_s3_bucket_name = var.config_s3_bucket_name
  variables = {
    SLACK_WEBHOOK = var.slack_webhook
    SLACK_CHANNEL = var.slack_channel
  }
}

#Module      :  GUARD DUTY
module "guardduty" {
  source                  = "git::https://github.com/clouddrove/terraform-aws-guardduty.git?ref=tags/0.12.0"
  name                    = "guardduty"
  application             = var.application
  environment             = var.environment
  label_order             = var.label_order
  guardduty_enable        = var.enabled && var.guardduty_enable
  ipset_format            = "TXT"
  ipset_iplist            = var.ipset_iplist
  threatintelset_activate = var.threatintelset_activate
  threatintelset_format   = "TXT"
  threatintelset_iplist   = var.threatintelset_iplist

  is_guardduty_member = var.is_guardduty_member
  member_list         = var.member_list
}