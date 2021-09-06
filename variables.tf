#Module      : LABEL
#Description : Terraform label module variables.
variable "name" {
  type        = string
  default     = ""
  description = "Name  (e.g. `app` or `cluster`)."
}

variable "application" {
  type        = string
  default     = ""
  description = "Application (e.g. `cd` or `clouddrove`)."
}

variable "environment" {
  type        = string
  default     = ""
  description = "Environment (e.g. `prod`, `dev`, `staging`)."
}

variable "label_order" {
  type        = list
  default     = []
  description = "Label order, e.g. `name`,`application`."
}

variable "managedby" {
  type        = string
  default     = "AnmolNagpal"
  description = "ManagedBy, eg 'CloudDrove' or 'AnmolNagpal'."
}

variable "attributes" {
  type        = list
  default     = []
  description = "Additional attributes (e.g. `1`)."
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter to be used between `organization`, `environment`, `name` and `attributes`."
}

variable "cloudtrail_s3_policy" {
  type        = string
  default     = ""
  description = "Policy for S3."
}

variable "tags" {
  type        = map
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "slack_webhook" {
  type        = string
  description = "The webhook of slack."
}

variable "target_bucket" {
  type        = string
  default     = ""
  description = "The name of the bucket that will receive the log objects."
}

variable "target_prefix" {
  type        = string
  default     = ""
  description = "To specify a key prefix for log objects."
}

variable "sse_algorithm" {
  type        = string
  default     = "AES256"
  description = "The server-side encryption algorithm to use. Valid values are AES256 and aws:kms."
}


variable "slack_channel" {
  type        = string
  description = "The channel of slack."
}

## Cloudtrail
variable "cloudtrail_enabled" {
  description = "The boolean flag whether cloudtrail module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "cloudwatch_logs_group_name" {
  type        = string
  default     = "iam_role_name"
  description = "The name of CloudWatch Logs group to which CloudTrail events are delivered."
}

variable "key_deletion_window_in_days" {
  type        = number
  default     = 10
  description = "Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days. Defaults to 30 days."
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 365
  description = "Number of days to retain logs for. CIS recommends 365 days.  Possible values are: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. Set to 0 to keep logs indefinitely."
}

variable "cloudtrail_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store configuration snapshots."
}

# analyzer
variable "analyzer_enable" {
  description = "The boolean flag whether alarm module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "type" {
  type        = string
  default     = "ACCOUNT"
  description = "Type of Analyzer. Valid value is currently only ACCOUNT. Defaults to ACCOUNT."
}


# Alarm
variable "alarm_enabled" {
  description = "The boolean flag whether alarm module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "unauthorized_api_calls" {
  type        = bool
  default     = true
  description = "If you want to create alarm for unauthorized api calls."
}

variable "no_mfa_console_signin" {
  type        = bool
  default     = true
  description = "If you want to create alarm when MFA not enabled on root user."
}

variable "root_usage" {
  type        = bool
  default     = true
  description = "If you want to create alarm when sign in with root user."
}

variable "iam_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in IAM."
}

variable "cloudtrail_cfg_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in cloudtrail cfg."
}

variable "console_signin_failures" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in cloudtrail cfg."
}

variable "security_group_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes on security groups."
}

variable "disable_or_delete_cmk" {
  type        = bool
  default     = true
  description = "If you want to create alarm when disable or delete in cmk."
}

variable "nacl_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in nacl."
}

variable "s3_bucket_policy_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in S3 policy."
}

variable "network_gw_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in network gateway."
}

variable "route_table_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in network gateway."
}

variable "vpc_changes" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in vpc."
}

variable "alarm_namespace" {
  description = "The namespace in which all alarms are set up."
  default     = "CISBenchmark"
}

## Guardduty
variable "guardduty_enable" {
  type        = bool
  default     = true
  description = "Enable monitoring and feedback reporting. Setting to false is equivalent to `suspending` GuardDuty. Defaults to true"
}

variable "guardduty_s3_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store guardduty files."
}

variable "ipset_iplist" {
  type        = list
  description = "IPSet list of trusted IP addresses"
  default     = []
}

variable "threatintelset_iplist" {
  type        = list
  description = "ThreatIntelSet list of known malicious IP addresses"
  default     = []
}

variable "threatintelset_activate" {
  type        = bool
  description = "Specifies whether GuardDuty is to start using the uploaded ThreatIntelSet"
  default     = true
}

variable "member_list" {
  type = list(object({
    account_id = string
    email      = string
    invite     = bool
  }))
  default     = []
  description = "The list of member accounts to be added. Each member list need to have values of account_id, member_email and invite boolean"
}

variable "is_guardduty_member" {
  type        = bool
  default     = false
  description = "Whether the account is a member account"
}

# Config
variable "config_enabled" {
  description = "The boolean flag whether config module is enabled or not. No resources are created when set to false."
  default     = true
}
variable "restricted_ports" {
  type        = bool
  default     = false
  description = "If you want to enable the restricted incoming port."
}

variable "restricted_ports_list" {
  type        = string
  default     = "{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"
  description = "This list of blocked ports."
}

variable "iam_mfa" {
  type        = bool
  default     = false
  description = "Check MFA is enabled."
}

variable "unused_credentials" {
  type        = bool
  default     = false
  description = "Check unused credentials in AWS account."
}

variable "user_no_policies" {
  type        = bool
  default     = false
  description = "Check user no policies."
}


variable "no_policies_with_full_admin_access" {
  type        = bool
  default     = false
  description = "Check user no policies with full admin access."
}

variable "acm_certificate_expiration_check" {
  type        = bool
  default     = false
  description = "Check ACM Certificates in your account are marked for expiration within the specified number of days."
}

variable "acm_days_to_expiration" {
  type        = number
  default     = 14
  description = "Specify the number of days before the rule flags the ACM Certificate as noncompliant."
}

variable "ec2_volume_inuse_check" {
  type        = bool
  default     = false
  description = "Checks whether EBS volumes are attached to EC2 instances."
}

variable "ebs_snapshot_public_restorable" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable."
}

variable "rds_storage_encrypted" {
  type        = bool
  default     = false
  description = "Checks whether storage encryption is enabled for your RDS DB instances."
}

variable "rds_instance_public_access_check" {
  type        = bool
  default     = false
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible."
}

variable "rds_snapshots_public_prohibited" {
  type        = bool
  default     = false
  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."
}

variable "guardduty_enabled_centralized" {
  type        = bool
  default     = false
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."
}

variable "s3_bucket_public_write_prohibited" {
  type        = bool
  default     = false
  description = "Checks that your S3 buckets do not allow public write access."
}

variable "eip_attached" {
  type        = bool
  default     = false
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."
}

variable "ec2_encrypted_volumes" {
  type        = bool
  default     = false
  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."
}

variable "iam_root_access_key" {
  type        = bool
  default     = false
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist."
}

variable "vpc_default_security_group_closed" {
  type        = bool
  default     = false
  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic."
}

variable "s3_bucket_ssl_requests_only" {
  type        = bool
  default     = false
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."
}

variable "config_cloudtrail_enabled" {
  type        = bool
  default     = false
  description = "Ensuring that the cloudtrail is enabled."
}

variable "multi_region_cloudtrail_enabled" {
  type        = bool
  default     = false
  description = "Ensuring that the multi-region-cloud-trail is enabled"
}

variable "instances_in_vpc" {
  type        = bool
  default     = false
  description = "Ensuring that all the instances in VPC"
}

variable "cloudwatch_log_group_encrypted" {
  type        = bool
  default     = false
  description = "Ensuring that log group is encrypted"
}

variable "iam_password_policy" {
  type        = bool
  default     = false
  description = "Ensuring that log group is encrypted"
}

variable "password_require_uppercase" {
  type        = bool
  default     = true
  description = "Require at least one uppercase character in password."
}

variable "password_require_lowercase" {
  type        = bool
  default     = true
  description = "Require at least one lowercase character in password."
}

variable "password_require_symbols" {
  type        = bool
  default     = true
  description = "Require at least one symbol in password."
}

variable "password_require_numbers" {
  type        = bool
  default     = true
  description = "Require at least one number in password."
}

variable "password_min_length" {
  type        = number
  default     = 16
  description = "Password minimum length."
}

variable "password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Number of passwords before allowing reuse."
}

variable "password_max_age" {
  type        = number
  default     = 90
  description = "Number of days before password expiration."
}

variable "config_s3_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store logs for aws  config."
}

# inspector
variable "inspector_enabled" {
  type        = bool
  default     = true
  description = "Whether Inspector is enabled or not."
}

variable "rules_package_arns" {
  type        = list(string)
  default     = []
  description = "The rules to be used during the run."
}

variable "schedule_expression" {
  type        = string
  default     = "cron(0 14 ? * THU *)" # Run every Thursday at 2PM UTC/9AM EST/10AM EDT
  description = "AWS Schedule Expression: https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html"
}