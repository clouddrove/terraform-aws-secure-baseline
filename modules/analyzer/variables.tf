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


variable "enabled" {
  type        = bool
  default     = false
  description = "Flag to control the module creation."
}

variable "managedby" {
  type        = string
  default     = "hello@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove'"
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
