## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

module "config" {
  source                = "../../../modules/config"

  name                  = "config"
  environment           = "security"
  label_order           = ["name", "environment"]
  config_s3_bucket_name = "config-bucketssss"
  enabled               = true


  # roles
  restricted_ports                   = true
  restricted_ports_list              = "{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"
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

  iam_password_policy        = false
  password_require_uppercase = true
  password_require_lowercase = true
  password_require_symbols   = true
  password_require_numbers   = true
  password_max_age           = 90
  slack_enabled              = false
  
  variables = {
    SLACK_WEBHOOK = "" # Webhook for the slack notification
    SLACK_CHANNEL = "" # Channel of the Slack where the notification will receive
  }
}