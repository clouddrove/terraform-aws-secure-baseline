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

variable "tags" {
  type        = map
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "cloudtrail_enabled" {
  description = "The boolean flag whether cloudtrail module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "alarm_enabled" {
  description = "The boolean flag whether alarm module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "config_enabled" {
  description = "The boolean flag whether config module is enabled or not. No resources are created when set to false."
  default     = true
}

variable "alarm_namespace" {
  description = "The namespace in which all alarms are set up."
  default     = "CISBenchmark"
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

variable "s3_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store configuration snapshots."
}

variable "config_s3_bucket_name" {
  type        = string
  description = "The name of the S3 bucket which will store logs for aws  config."
}


variable "slack_webhook" {
  type        = string
  description = "The webhook of slack."
}


variable "slack_channel" {
  type        = string
  description = "The channel of slack."
}


variable "s3_policy" {
  type        = string
  description = "policy for s3."
}
