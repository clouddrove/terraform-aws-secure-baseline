variable "enable_default_standards" {
  description = "Flag to indicate whether default standards should be enabled"
  type        = bool
  default     = true
}

variable "control_finding_generator" {
  description = <<-DOC
    Updates whether the calling account has consolidated control findings turned on. 
    If the value for this field is set to SECURITY_CONTROL, 
    Security Hub generates a single finding for a control check even when the check applies to multiple enabled standards. 
    If the value for this field is set to STANDARD_CONTROL, 
    Security Hub generates separate findings for a control check when the check applies to multiple enabled standards. 
    For accounts that are part of an organization, 
    this value can only be updated in the administrator account.
  DOC
  type        = string
  default     = null
}

variable "auto_enable_controls" {
  description = <<-DOC
    Whether to automatically enable new controls when they are added to standards that are enabled. 
    By default, this is set to true, and new controls are enabled automatically. 
    To not automatically enable new controls, set this to false.
  DOC
  type        = bool
  default     = true
}

variable "enabled_standards" {
  description = <<-DOC
    The possible values are:
    - standards/aws-foundational-security-best-practices/v/1.0.0
    - ruleset/cis-aws-foundations-benchmark/v/1.2.0
    - standards/pci-dss/v/3.2.1
  DOC
  type        = list(any)
  default = [
    "standards/aws-foundational-security-best-practices/v/1.0.0",
    "ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  ]
}

variable "enabled_products" {
  description = <<-DOC
    The possible values are:
    - product/aws/guardduty
    - product/aws/inspector
    - product/aws/macie
  DOC
  type        = list(any)
  default = [
    "product/aws/guardduty",
    "product/aws/inspector",
    "product/aws/macie"
  ]
}

variable "security_hub_enabled" {
  type        = bool
  default     = false
  description = "To Enable seucirty-hub in aws account"
}

variable "member_details" {
  type = list(object({
    account_id = string
    mail_id    = optional(string, null)
    invite     = optional(bool, null)
  }))
  default = []
}