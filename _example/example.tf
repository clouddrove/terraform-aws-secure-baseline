provider "aws" {
  region = "eu-west-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

module "secure_baseline" {
  source = "./../"

  application = "clouddrove"
  environment = "test"
  label_order = ["environment", "application", "name"]

  enabled       = true
  slack_webhook = "https://hooks.slack.com/services/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uEG4TW"
  slack_channel = "testing"

  # cloudtrail
  cloudtrail_enabled                = true
  key_deletion_window_in_days       = 10
  cloudwatch_logs_retention_in_days = 365
  cloudwatch_logs_group_name        = "cloudtrail-log-group"
  cloudtrail_bucket_name            = "cloudtrail-bucket-logs"
  EVENT_IGNORE_LIST                 = jsonencode(["^Describe*", "^Assume*", "^List*", "^Get*", "^Decrypt*", "^Lookup*", "^BatchGet*", "^CreateLogStream$", "^RenewRole$", "^REST.GET.OBJECT_LOCK_CONFIGURATION$", "TestEventPattern", "TestScheduleExpression", "CreateNetworkInterface", "ValidateTemplate"])
  EVENT_ALERT_LIST                  = jsonencode(["DetachRolePolicy", "ConsoleLogin"])
  USER_IGNORE_LIST                  = jsonencode(["^awslambda_*", "^aws-batch$", "^bamboo*", "^i-*", "^[0-9]*$", "^ecs-service-scheduler$", "^AutoScaling$", "^AWSCloudFormation$", "^CloudTrailBot$", "^SLRManagement$"])
  SOURCE_LIST                       = jsonencode(["aws-sdk-go"])


  # Alarm
  alarm_enabled            = true
  alarm_namespace          = "Alert_Alarm"
  unauthorized_api_calls   = true
  no_mfa_console_signin    = true
  root_usage               = true
  iam_changes              = true
  cloudtrail_cfg_changes   = true
  console_signin_failures  = true
  disable_or_delete_cmk    = true
  s3_bucket_policy_changes = true
  security_group_changes   = true
  nacl_changes             = true
  network_gw_changes       = true
  route_table_changes      = true
  vpc_changes              = true


  ## Config
  config_enabled                     = true
  config_s3_bucket_name              = "config-bucket"
  restricted_ports                   = true
  iam_mfa                            = true
  unused_credentials                 = true
  user_no_policies                   = true
  no_policies_with_full_admin_access = true
  acm_certificate_expiration_check   = true
  ec2_volume_inuse_check             = true
  ebs_snapshot_public_restorable     = true
  rds_instance_public_access_check   = true
  rds_snapshots_public_prohibited    = true
  guardduty_enabled_centralized      = true
  s3_bucket_public_write_prohibited  = true
  eip_attached                       = false
  ec2_encrypted_volumes              = true
  iam_root_access_key                = true
  vpc_default_security_group_closed  = false
  s3_bucket_ssl_requests_only        = false
  multi_region_cloudtrail_enabled    = true
  instances_in_vpc                   = true
  cloudwatch_log_group_encrypted     = false
  rds_storage_encrypted              = true
  restricted_ports_list              = "{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"

  # guardduty
  guardduty_enable         = true
  guardduty_s3_bucket_name = "guardduty-files"
  ipset_iplist             = ["10.10.0.0/16", "172.16.0.0/16", ]
  threatintelset_activate  = false
  threatintelset_iplist    = ["192.168.2.0/32", "4.4.4.4", ]

  ## Inspector
  inspector_enabled = true
  rules_package_arns = [
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6",
  ]
  schedule_expression = "cron(0/10 * ? * * *)"
}
# analyzer
analyzer_enable = true
type            = "ACCOUNT"

