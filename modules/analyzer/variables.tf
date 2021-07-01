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

variable "tags" {
  type        = map(any)
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  type        = bool
  default     = false
  description = "Flag to control the module creation."
}

variable "managedby" {
  type        = string
  default     = "anmol@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove' or 'AnmolNagpal'."
}

variable "label_order" {
  type        = list(any)
  default     = []
  description = "Label order, e.g. `name`,`application`."
}

## IAM Access Analyzer
variable "type" {
  type        = string
  default     = ""
  description = "Type of Analyzer. Valid value is currently only ACCOUNT. Defaults to ACCOUNT."
}

## Cloud Watch Event

variable "rule_iam_role_arn" {
  default     = null
  description = "The Amazon Resource Name (ARN) associated with the role that is used for target invocation."
}

variable "target_iam_role_arn" {
  default     = null
  description = "The Amazon Resource Name (ARN) associated with the role that is used for target invocation."
}

variable "variables" {
  default     = {}
  description = "The environment variables for lambda function."

}