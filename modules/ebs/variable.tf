variable "enabled" {
  type        = bool
  default     = false
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
}

variable "enable_default_ebs_encryption" {
  type        = bool
  default     = true
  description = "The boolean flag whether default EBS Encryption is enabled or not."
}
