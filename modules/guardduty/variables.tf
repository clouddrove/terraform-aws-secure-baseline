# Module     : Label
# Description: Terraform label module variables
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
  default     = "anmol@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove' or 'AnmolNagpal'."
}

variable "guardduty_enable" {
  type        = bool
  default     = true
  description = "Enable monitoring and feedback reporting. Setting to false is equivalent to `suspending` GuardDuty. Defaults to true"
}

variable "ipset_iplist" {
  type        = list
  description = "IPSet list of trusted IP addresses"
  default     = []
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

variable "threatintelset_iplist" {
  type        = list
  description = "ThreatIntelSet list of known malicious IP addresses"
  default     = []
}

variable "ipset_format" {
  type        = string
  default     = "TXT"
  description = "The format of the file that contains the IPSet. Valid values: `TXT` | `STIX` | `OTX_CSV` | `ALIEN_VAULT` | `PROOF_POINT` | `FIRE_EYE`."
}

variable "threatintelset_format" {
  type        = string
  default     = "TXT"
  description = "The format of the file that contains the ThreatIntelSet"
}

variable "disable_email_notification" {
  type        = bool
  default     = true
  description = "Boolean whether an email notification is sent to the accounts."
}

variable "finding_publishing_frequency" {
  type        = string
  default     = "SIX_HOURS"
  description = "Valid values for standalone and master accounts: `FIFTEEN_MINUTES`, `ONE_HOUR`, `SIX_HOURS`"
}

variable "bucket_name" {
  type        = string
  default     = ""
  description = "Name of the S3 bucket to use"
}

variable "is_guardduty_member" {
  type        = bool
  default     = false
  description = "Whether the account is a member account"
}

variable "ipset_activate" {
  type        = bool
  description = "Specifies whether GuardDuty is to start using the uploaded IPSet"
  default     = true
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

variable "enabled" {
  type        = bool
  default     = false
  description = "Flag to control the module creation."
}

variable "rule_iam_role_arn" {
  default     = null
  description = "The Amazon Resource Name (ARN) associated with the role that is used for target invocation."
}

variable "is_enabled" {
  type        = bool
  default     = true
  description = "Whether the rule should be enabled (defaults to true)."
}

variable "target_iam_role_arn" {
  default     = null
  description = "The Amazon Resource Name (ARN) associated with the role that is used for target invocation."
}

variable "variables" {
  default     = {}
  description = "The environment variables for lambda function."

}