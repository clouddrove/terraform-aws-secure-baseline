#Module      : LABEL
#Description : Terraform label module variables.
variable "name" {
  type        = string
  default     = ""
  description = "Name  (e.g. `app` or `cluster`)."
}

variable "managedby" {
  type        = string
  default     = "hello@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove'"
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

variable "attributes" {
  type        = list(any)
  default     = []
  description = "Additional attributes (e.g. `1`)."
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter to be used between `organization`, `environment`, `name` and `attributes`."
}

variable "tags" {
  type        = map(any)
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
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
  type        = string
  default     = ""
  description = "The namespace in which all alarms are set up."
}

variable "cloudtrail_log_group_name" {
  type        = string
  default     = ""
  description = "The name of the CloudWatch Logs group to which CloudTrail events are delivered."
}

variable "variables" {
  default     = {}
  description = "The environment variables for lambda function."
}

