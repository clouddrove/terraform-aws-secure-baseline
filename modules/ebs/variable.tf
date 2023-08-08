variable "enabled" {
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
  default     = false
}

variable "enable_default_ebs_encryption" {
  description = "The boolean flag whether default EBS Encryption is enabled or not."
  default     = true
}
