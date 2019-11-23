provider "aws" {
  region = "eu-west-1"
}

module "cloudtrail" {
  source = "git::https://github.com/clouddrove/terraform-aws-cloudtrail-baseline.git"
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

module "alarm_baseline" {
  source = "git::https://github.com/clouddrove/terraform-aws-alarm-baseline.git"
  name        = "alarm"
  application = "clouddrove"
  environment = "test"
  label_order = var.label_order

  enabled                   = var.enabled
  alarm_namespace           = var.alarm_namespace
  cloudtrail_log_group_name = module.cloudtrail.log_group.name
}

module "config-baseline" {
  source = "git::https://github.com/clouddrove/terraform-aws-config-baseline.git"

  name        = "config"
  application = var.application
  environment = var.environment
  label_order = var.label_order
  enabled     = var.enabled
  config_s3_bucket_name = var.config_s3_bucket_name
}
