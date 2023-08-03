#Module      : LABEL
#Description : Terraform label module variables.
variable "environment" {
  type        = string
  default     = ""
  description = "Environment (e.g. `prod`, `dev`, `staging`)."
}

variable "label_order" {
  type        = list(any)
  default     = []
  description = "Label order, e.g. `name`,`application`."
}

variable "managedby" {
  type        = string
  default     = "hello@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove'"
}

variable "attributes" {
  type        = list(any)
  default     = []
  description = "Additional attributes (e.g. `1`)."
}

variable "cloudtrail_s3_policy" {
  type        = string
  default     = ""
  description = "Policy for S3."
}

variable "event_ignore_list" {
  type        = string
  default     = ""
  description = "Event List which event is ignore."
}

variable "event_alert_list" {
  type        = string
  default     = ""
  description = "Event List which event is not ignore."
}

variable "user_ignore_list" {
  type        = string
  default     = ""
  description = "User List which event is ignore."
}

variable "source_list" {
  type        = string
  default     = ""
  description = "Event Source List which event is ignore."
}

variable "tags" {
  type        = map(any)
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "slack_webhook" {
  type        = string
  default     = ""
  description = "The webhook of slack."
}

variable "slack_channel" {
  type        = string
  default     = ""
  description = "The channel of slack."
}

#Variable    : CloudTrail
#Description : Terraform cloudtrail module variables.

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
  default     = "Cloudtrail"
  description = "The name of the S3 bucket which will store configuration snapshots."
}

variable "include_global_service_events" {
  type        = bool
  default     = true
  description = "Specifies whether the trail is publishing events from global services such as IAM to the log files."
}

variable "cloud_watch_logs_role_arn" {
  type        = string
  default     = ""
  description = "Specifies the role for the CloudWatch Logs endpoint to assume to write to a user’s log group."
  sensitive   = true
}

variable "additional_member_root_arn" {
  type        = list(any)
  default     = []
  description = "Additional member root user arn."
}

variable "additional_member_trail" {
  type        = list(any)
  default     = []
  description = "Additional member trails."
}

variable "additional_member_account_id" {
  type        = list(any)
  default     = []
  description = "Additional member account id."
}

variable "insight_selector" {
  type = list(object({
    insight_type = string
  }))

  description = "Specifies an insight selector for type of insights to log on a trail"
  default     = []
}

variable "event_selector" {
  type = list(object({
    include_management_events = bool
    read_write_type           = string

  }))
  description = "Specifies an event selector for enabling data event logging. See: https://www.terraform.io/docs/providers/aws/r/cloudtrail.html for details on this variable"
  default     = []
}
variable "sns_topic_name" {
  type        = string
  description = "Specifies the name of the Amazon SNS topic defined for notification of log file delivery"
  default     = null
}

variable "s3_mfa_delete" {
  default     = false
  description = "mfa enable for bucket."
}

variable "object_lock_configuration" {
  type = object({
    mode  = string
    days  = number
    years = number
  })
  default     = null
  description = "With S3 Object Lock, you can store objects using a write-once-read-many (WORM) model. Object Lock can help prevent objects from being deleted or overwritten for a fixed amount of time or indefinitely."

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

variable "aws_config_changes_enabled" {
  type        = bool
  default     = true
  description = "If you want to create alarm when any changes in aws config."
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
  default     = "guardduty-bucket"
}

variable "ipset_iplist" {
  type        = list(any)
  description = "IPSet list of trusted IP addresses"
  default     = []
}

variable "threatintelset_iplist" {
  type        = list(any)
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

#shield
variable "shield_enable" {
  description = "The boolean flag whether shield module is enabled or not. No resources are created when set to false."
  default     = false
}

variable "resource_arn" {
  type        = string
  default     = ""
  description = "The ARN (Amazon Resource Name) of the resource to be protected."
}

#ebs
variable "default_ebs_enable" {
  description = "The boolean flag whether Default EBS  module is enabled or not. No resources are created when set to false."
  default     = false
}

#Security Hub

variable "security_hub_enable" {
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "enable_cis_standard" {
  description = "Boolean whether CIS standard is enabled."
  default     = true
}

variable "enable_pci_dss_standard" {
  description = "Boolean whether PCI DSS standard is enabled."
  default     = true
}

variable "enable_aws_foundational_standard" {
  description = "Boolean whether AWS Foundations standard is enabled."
  default     = true
}

#IAM baseline
variable "master_iam_role_name" {
  description = "The name of the IAM Master role."
  default     = "IAM-Master"
}

variable "master_iam_role_policy_name" {
  description = "The name of the IAM Master role policy."
  default     = "IAM-Master-Policy"
}

variable "manager_iam_role_name" {
  description = "The name of the IAM Manager role."
  default     = "IAM-Manager"
}

variable "manager_iam_role_policy_name" {
  description = "The name of the IAM Manager role policy."
  default     = "IAM-Manager-Policy"
}

variable "support_iam_role_name" {
  description = "The name of the the support role."
  default     = "IAM-Support"
}

variable "support_iam_role_policy_name" {
  description = "The name of the support role policy."
  default     = "IAM-Support-Role"
}

variable "support_iam_role_principal_arn" {
  default     = ""
  description = "The ARN of the IAM principal element by which the support role could be assumed."

}

variable "max_password_age" {
  default     = 120
  description = "The number of days that an user password is valid."

}

variable "minimum_password_length" {
  default     = 14
  description = "Minimum length to require for user passwords."
}

variable "require_lowercase_characters" {
  default     = true
  description = "Whether to require lowercase characters for user passwords."
}

variable "require_numbers" {
  default     = true
  description = "Whether to require numbers for user passwords."
}

variable "require_uppercase_characters" {
  default     = true
  description = "Whether to require uppercase characters for user passwords."
}

variable "require_symbols" {
  default     = true
  description = "Whether to require symbols for user passwords."
}

variable "allow_users_to_change_password" {
  default     = true
  description = "Whether to allow users to change their own password."
}

variable "aws_iam_account_password_policy" {
  type    = bool
  default = true
}

variable "enable_iam_baseline" {
  type    = bool
  default = true
}
