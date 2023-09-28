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

variable "managedby" {
  type        = string
  default     = "hello@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove'"
}


variable "enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
}

variable "resource_arn" {
  type        = string
  default     = ""
  description = "The ARN (Amazon Resource Name) of the resource to be protected."
}
