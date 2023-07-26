#Variable    : LABEL
#Description : Terraform label module variables.
variable "name" {
  type        = string
  default     = ""
  description = "Name  (e.g. `app` or `cluster`)."
}

variable "environment" {
  type        = string
  default     = ""
  description = "Environment (e.g. `prod`, `dev`, `staging`, `test`)."
}

variable "repository" {
  type        = string
  default     = "https://github.com/clouddrove/terraform-aws-secure-baseline"
  description = "Terraform current module repo"
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

#Variable    : CloudTrail
#Description : Terraform cloudtrail module variables.

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account."
}

variable "enable_logging" {
  type        = bool
  default     = true
  description = "Enable logging for the trail."
}

variable "enable_log_file_validation" {
  type        = bool
  default     = true
  description = "Specifies whether log file integrity validation is enabled. Creates signed digest for validated contents of logs."
}

variable "is_multi_region_trail" {
  type        = bool
  default     = false
  description = "Specifies whether the trail is created in the current region or in all regions"
}

variable "include_global_service_events" {
  type        = bool
  default     = true
  description = "Specifies whether the trail is publishing events from global services such as IAM to the log files."
}

variable "enabled_cloudtrail" {
  type        = bool
  default     = false
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
}

variable "cloud_watch_logs_role_arn" {
  type        = string
  default     = ""
  description = "Specifies the role for the CloudWatch Logs endpoint to assume to write to a user’s log group."
  sensitive   = true
}

variable "cloud_watch_logs_group_arn" {
  type        = string
  default     = ""
  description = "Specifies a log group name using an Amazon Resource Name (ARN), that represents the log group to which CloudTrail logs will be delivered."
  sensitive   = true
}

variable "slack_webhook" {
  type        = string
  default     = ""
  description = "Webhook of slack."
}

variable "slack_channel" {
  type        = string
  default     = ""
  description = "Channel of slack."
}

variable "iam_role_name" {
  type        = string
  default     = "CloudTrail-CloudWatch-Delivery-Role"
  description = "The name of the IAM Role to be used by CloudTrail to delivery logs to CloudWatch Logs group."
}

variable "enable_cloudwatch" {
  type        = bool
  default     = true
  description = "If true, deploy the resources for cloudwatch in the module."
}

variable "cloudwatch_log_group_name" {
  description = "The name of the CloudWatch Log Group that receives CloudTrail events."
  default     = "cloudtrail-events"
  type        = string
}

variable "log_retention_days" {
  description = "Number of days to keep AWS logs around in specific log group."
  default     = 90
  type        = string
}


#Variable    : S3 Bucket
#Description : Terraform variables for s3 bucket.

variable "bucket_environment" {
  type        = string
  default     = ""
  description = "Environment (e.g. `prod`, `dev`, `staging`, `test`)."
}

variable "s3_bucket_name" {
  type        = string
  default     = ""
  description = "The name of the S3 bucket which will store configuration snapshots."
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

variable "event_selector" {
  type = list(object({
    include_management_events = bool
    read_write_type           = string
  }))

  description = "Specifies an event selector for enabling data event logging. See: https://www.terraform.io/docs/providers/aws/r/cloudtrail.html for details on this variable"
  default     = []
}

variable "insight_selector" {
  type = list(object({
    insight_type = string
  }))

  description = "Specifies an insight selector for type of insights to log on a trail"
  default     = []
}

variable "sns_topic_name" {
  type        = string
  default     = null
  description = "Specifies the name of the Amazon SNS topic defined for notification of log file delivery"
}

variable "create_bucket" {
  type        = bool
  default     = true
  description = "Conditionally create S3 bucket."
}

variable "bucket_versioning" {
  type        = bool
  default     = true
  description = "Enable Versioning of S3."
}

variable "bucket_policy" {
  type        = bool
  default     = false
  description = "Conditionally create S3 bucket policy."
}

variable "lifecycle_expiration_enabled" {
  type        = bool
  default     = true
  description = "Specifies expiration lifecycle rule status."
}

variable "lifecycle_days_to_expiration" {
  type        = number
  default     = 30
  description = "Specifies the number of days after object creation when the object expires."
}

variable "force_destroy" {
  type        = bool
  default     = true
  description = "A boolean that indicates all objects should be deleted from the bucket so that the bucket can be destroyed without error. These objects are not recoverable."
}

variable "block_public_acls" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should block public ACLs for this bucket. Defaults to false. Enabling this setting does not affect existing policies or ACLs. When set to true causes the following behavior:
    - PUT Bucket acl and PUT Object acl calls will fail if the specified ACL allows public access.
    - PUT Object calls will fail if the request includes an object ACL. 
  EOF
}

variable "block_public_policy" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should block public bucket policies for this bucket. Defaults to false. Enabling this setting does not affect the existing bucket policy. When set to true causes Amazon S3 to:
    - Reject calls to PUT Bucket policy if the specified bucket policy allows public access.
  EOF
}

variable "ignore_public_acls" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should ignore public ACLs for this bucket. Defaults to false. Enabling this setting does not affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set. When set to true causes Amazon S3 to:
    - Ignore public ACLs on this bucket and any objects that it contains.
  EOF
}

variable "restrict_public_buckets" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should restrict public bucket policies for this bucket. Defaults to false. Enabling this setting does not affect the previously stored bucket policy, except that public and cross-account access within the public bucket policy, including non-public delegation to specific accounts, is blocked. When set to true:
    - Only the bucket owner and AWS Services can access this buckets if it has a public policy.
  EOF
}

#Variable    : KMS
#Description : Terraform KMS resource variables.

variable "kms_enabled" {
  type        = bool
  default     = false
  description = "If true, deploy the resources for kms in the module. Note: Supports in only single cloudtrail management."
}

variable "enable_key_rotation" {
  type        = string
  default     = true
  description = "Specifies whether key rotation is enabled."
}

variable "key_deletion_window_in_days" {
  type        = number
  default     = 10
  description = "Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days. Defaults to 30 days."
}