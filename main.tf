
#Module      : CLOUDTRAIL
#Description : Terraform module to provision an AWS CloudTrail with encrypted S3 bucket.
#              This bucket is used to store CloudTrail logs.
module "cloudtrail" {
  source = "git::https://github.com/clouddrove/terraform-aws-cloudtrail-baseline.git?ref=tags/0.12.0"
  name        = "trails"
  application = var.application
  environment = var.environment
  label_order = var.label_order
  enabled                           = var.enabled
  iam_role_name                     = "CloudTrail-CloudWatch-Delivery-Role"
  iam_role_policy_name              = "CloudTrail-CloudWatch-Delivery-Policy"
  account_type                      = "individual"
  key_deletion_window_in_days       = var.key_deletion_window_in_days
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  cloudwatch_logs_group_name        = var.cloudwatch_logs_group_name
  s3_bucket_name                    = var.s3_bucket_name
}

#Module      : ALARM BASELINE
#Description : Provides a CloudWatch Metric Alarm resource.
module "alarm_baseline" {
  source = "git::https://github.com/clouddrove/terraform-aws-alarm-baseline.git?ref=tags/0.12.0"
  name        = "alarm"
  application = var.application
  environment = var.environment
  label_order = var.label_order

  enabled                   = var.enabled
  alarm_namespace           = var.alarm_namespace
  cloudtrail_log_group_name = module.cloudtrail.log_group_name
}

#Module      : CONFIG BASELINE
#Description : Manages status (recording / stopped) of an AWS Config Configuration Recorder.
module "config-baseline" {
  source = "git::https://github.com/clouddrove/terraform-aws-config-baseline.git?ref=tags/0.12.0"
  name        = "config"
  application = var.application
  environment = var.environment
  label_order = var.label_order
  enabled     = var.enabled
  config_s3_bucket_name = var.config_s3_bucket_name
}
