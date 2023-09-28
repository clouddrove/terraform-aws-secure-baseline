variable "enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
}

variable "enable_cis_standard" {
  type        = bool
  description = "Boolean whether CIS standard is enabled."
  default     = true
}

variable "enable_pci_dss_standard" {
  type        = bool
  default     = true
  description = "Boolean whether PCI DSS standard is enabled."
}

variable "enable_aws_foundational_standard" {
  type        = bool
  default     = true
  description = "Boolean whether AWS Foundations standard is enabled."
}

variable "member_accounts" {
  description = "A list of IDs and emails of AWS accounts which associated as member accounts."
  type = list(object({
    account_id = string
    email      = string
  }))
  default = []
}
