#Module      : LABEL
#Description : Terraform label module variables.
variable "name" {
  type        = string
  default     = ""
  description = "Name  (e.g. `app` or `cluster`)."
}


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

variable "enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
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

variable "cloudwatch_logs_group_name" {
  type        = string
  default     = "iam_role_name"
  description = "The name of CloudWatch Logs group to which CloudTrail events are delivered."
}

variable "cloudwatch_logs_retention_in_days" {
  type        = number
  default     = 365
  description = "Number of days to retain logs for. CIS recommends 365 days.  Possible values are: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. Set to 0 to keep logs indefinitely."
}

variable "iam_role_name" {
  type        = string
  default     = "CloudTrail-CloudWatch-Delivery-Role-prakash"
  description = "The name of the IAM Role to be used by CloudTrail to delivery logs to CloudWatch Logs group."
}

variable "iam_role_policy_name" {
  type        = string
  default     = "CloudTrail-CloudWatch-Delivery-Policy"
  description = "The name of the IAM Role Policy to be used by CloudTrail to delivery logs to CloudWatch Logs group."
}

variable "s3_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store configuration snapshots."
}

variable "key_arn" {
  type        = string
  default     = ""
  description = "The arn of the KMS."
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = "Specifies whether the trail is an AWS Organizations trail. Organization trails log events for the master account and all member accounts. Can only be created in the organization master account."
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

variable "s3_policy" {
  type        = string
  default     = ""
  description = "Policy of s3."
}

variable "s3_mfa_delete" {
  type        = bool
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
variable "managedby" {
  type        = string
  default     = "hello@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove'"
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
  default     = null
  description = "Specifies the name of the Amazon SNS topic defined for notification of log file delivery"
}
