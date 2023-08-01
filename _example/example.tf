provider "aws" {
  region = "us-west-2"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}


module "cloudtrail" {
  source = "../modules/cloudtrail"

  name        = "cloudtrail-testing"
  environment = "security"
  label_order = ["name", "environment"]

  enabled_cloudtrail            = true
  key_deletion_window_in_days   = 10
  bucket_policy                 = true
  is_multi_region_trail         = true
  log_retention_days            = 90
  cloudwatch_log_group_name     = "cloudtrail-log-group"
  include_global_service_events = true
  is_organization_trail         = false
  kms_enabled                   = true

  event_selector = [{
    read_write_type           = "All"
    include_management_events = true

    data_resource = [
      {
        type   = "AWS::Lambda::Function"
        values = ["arn:aws:lambda"]
      },
    ]
    }
  ]
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
}

module "guardduty" {
  source = "../modules/guardduty"

  name                    = "test-guardduty"
  label_order             = ["name"]
  enabled                 = true
  bucket_name             = "secure-baseline-guardduty"
  ipset_format            = "TXT"
  ipset_iplist            = ["10.10.0.0/16", "10.20.0.0/16", "10.30.0.0/16"]
  threatintelset_activate = true
  threatintelset_format   = "TXT"

  finding_publishing_frequency = "ONE_HOUR"

  is_guardduty_member      = false
  organization_auto_enable = false
  guardduty_admin_id       = "112233445567"

  datasources = {
    s3_logs                = true,
    kubernetes_audit_logs  = false,
    malware_protection_ebs = true
  }

  # member_list         = [
  #   {
  #     account_id = "560633484280",
  #     invite     = true
  #   }
  # ]

  slack_enabled = false
  variables = {
    minSeverityLevel = "LOW"
    webHookUrl       = "" #var.slack_webhook
    slackChannel     = "" #var.slack_channel
  }
}

module "secure_baseline" {
  source = "./../"

  environment = "test"
  label_order = ["environment", "name"]

  enabled       = false
  slack_webhook = ""
  slack_channel = ""


  # Alarm
  alarm_enabled            = false
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
  config_enabled                     = false
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
  guardduty_enable         = false
  guardduty_s3_bucket_name = "guardduty-files"
  ipset_iplist             = ["10.10.0.0/16", "172.16.0.0/16", ]
  threatintelset_activate  = false
  threatintelset_iplist = [
    "192.168.2.0/32",
    "4.4.4.4",
  ]

  ## Inspector
  inspector_enabled = false
  rules_package_arns = [
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6",
  ]
  schedule_expression = "cron(0/10 * ? * * *)"

  # analyzer
  analyzer_enable = true
  type            = "ACCOUNT"

  # Shield        # Don't enable it for testing, it is too costly service right now.
  shield_enable = false

  # EBS
  default_ebs_enable = false

  # Security Hub
  security_hub_enable = false

  # IAM baseline
  ##IAM
  enable_iam_baseline          = false
  master_iam_role_name         = "IAM-Master"
  master_iam_role_policy_name  = "IAM-master-Policy"
  manager_iam_role_name        = "IAM-manager"
  manager_iam_role_policy_name = "IAM-Manager-Policy"
  support_iam_role_name        = "IAM-Policy"
  support_iam_role_policy_name = "IAM-Support-Role"

  #Password policy

  aws_iam_account_password_policy = true
  minimum_password_length         = 24
  password_reuse_prevention       = 24
  require_lowercase_characters    = true
  require_numbers                 = true
  require_uppercase_characters    = true
  require_symbols                 = true
  allow_users_to_change_password  = true
  max_password_age                = 120
}