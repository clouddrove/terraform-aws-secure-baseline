# Module     : Label
# Description: Terraform label module variables
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

variable "guardduty_enable" {
  type        = bool
  default     = true
  description = "Enable monitoring and feedback reporting. Setting to false is equivalent to `suspending` GuardDuty. Defaults to true"
}

variable "organization_auto_enable" {
  type        = bool
  default     = false
  description = "When this setting is enabled, all new accounts that are created in, or added to, the organization are added as a member accounts of the organization’s GuardDuty delegated administrator and GuardDuty is enabled in that AWS Region."
}

variable "guardduty_admin_id" {
  type        = string
  default     = ""
  description = "AWS account identifier to designate as a delegated administrator for GuardDuty."
}

variable "slack_enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this slack notification is enabled or not. No resources are created when set to false."
}

variable "ipset_iplist" {
  type        = list(any)
  description = "IPSet list of trusted IP addresses"
  default     = []
}

variable "threatintelset_iplist" {
  type        = list(any)
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

variable "create_bucket" {
  type        = bool
  default     = true
  description = "Conditionally create S3 bucket."
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
    email      = optional(string)
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

variable "target_iam_role_arn" {
  default     = null
  description = "The Amazon Resource Name (ARN) associated with the role that is used for target invocation."
}

variable "variables" {
  default     = {}
  description = "The environment variables for lambda function."

}

variable "datasources" {
  type = any
  default = {
    s3_logs                = true,
    kubernetes_audit_logs  = true,
    malware_protection_ebs = true
  }
}

variable "enable_s3_protection" {
  description = "Configure and enable S3 protection. Defaults to `true`."
  type        = bool
  default     = true
}

variable "enable_kubernetes_protection" {
  description = "Configure and enable Kubernetes audit logs as a data source for Kubernetes protection. Defaults to `true`."
  type        = bool
  default     = true
}

variable "enable_malware_protection" {
  description = "Configure and enable Malware Protection as data source for EC2 instances with findings for the detector. Defaults to `true`."
  type        = bool
  default     = true
}


## S3

variable "block_public_acls" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should block public ACLs for this bucket. Defaults to false. Enabling this setting does not affect existing policies or ACLs. When set to true causes the following behavior:
    - PUT Bucket acl and PUT Object acl calls will fail if the specified ACL allows public access.
    - PUT Object calls will fail if the request includes an object ACL. 
  EOF
}

variable "block_public_policy" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should block public bucket policies for this bucket. Defaults to false. Enabling this setting does not affect the existing bucket policy. When set to true causes Amazon S3 to:
    - Reject calls to PUT Bucket policy if the specified bucket policy allows public access.
  EOF
}

variable "ignore_public_acls" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should ignore public ACLs for this bucket. Defaults to false. Enabling this setting does not affect the persistence of any existing ACLs and doesn't prevent new public ACLs from being set. When set to true causes Amazon S3 to:
    - Ignore public ACLs on this bucket and any objects that it contains.
  EOF
}

variable "restrict_public_buckets" {
  type        = bool
  default     = true
  description = <<EOF
    Whether Amazon S3 should restrict public bucket policies for this bucket. Defaults to false. Enabling this setting does not affect the previously stored bucket policy, except that public and cross-account access within the public bucket policy, including non-public delegation to specific accounts, is blocked. When set to true:
    - Only the bucket owner and AWS Services can access this buckets if it has a public policy.
  EOF
}