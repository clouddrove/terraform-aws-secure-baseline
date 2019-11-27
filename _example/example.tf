provider "aws" {
  region = "eu-west-1"
}

module "secure_baseline" {
  source = "git::https://github.com/clouddrove/terraform-aws-secure-baseline.git?ref=tags/0.12.0"

  application = "clouddrove"
  environment = "test"
  label_order = ["environment", "application", "name"]

  enabled                           = true
  key_deletion_window_in_days       = 10
  cloudwatch_logs_retention_in_days = 365
  cloudwatch_logs_group_name        = "cloudtrail-log-group"
  alarm_namespace                   = "Alert_Alarm"

  s3_bucket_name                    = "cloudtrail-bucket"
  config_s3_bucket_name             = "config-bucket"
}
