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
  type        = list(any)
  default     = []
  description = "Label order, e.g. `name`,`application`."
}

variable "attributes" {
  type        = list(any)
  default     = []
  description = "Additional attributes (e.g. `1`)."
}

variable "delimiter" {
  type        = string
  default     = "-"
  description = "Delimiter to be used between `organization`, `environment`, `name` and `attributes`."
}

variable "tags" {
  type        = map(any)
  default     = {}
  description = "Additional tags (e.g. map(`BusinessUnit`,`XYZ`)."
}

variable "enabled" {
  type        = bool
  default     = true
  description = "The boolean flag whether this module is enabled or not. No resources are created when set to false."
}

variable "config_s3_bucket_name" {
  type        = string
  default     = ""
  description = "The name of the S3 bucket which will store configuration snapshots."
}

variable "delivery_frequency" {
  type        = string
  default     = "One_Hour"
  description = "The frequency which AWS Config sends a snapshot into the S3 bucket."

}

variable "include_global_resource_types" {
  type        = bool
  default     = true
  description = "Specifies whether AWS Config includes all supported types of global resources with the resources that it records."
}

variable "variables" {
  default     = {}
  description = "The environment variables for lambda function."

}

variable "managedby" {
  type        = string
  default     = "anmol@clouddrove.com"
  description = "ManagedBy, eg 'CloudDrove' or 'AnmolNagpal'."
}

variable "config_max_execution_frequency" {
  type        = string
  default     = "TwentyFour_Hours"
  description = "The maximum frequency with which AWS Config runs evaluations for a rule."
}

variable "restricted_ports" {
  type        = bool
  default     = true
  description = "If you want to enable the restricted incoming port."
}

variable "restricted_ports_list" {
  type        = string
  default     = "{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"
  description = "This list of blocked ports."
}

variable "iam_mfa" {
  type        = bool
  default     = true
  description = "Check MFA is enabled."
}

variable "unused_credentials" {
  type        = bool
  default     = true
  description = "Check unused credentials in AWS account."
}

variable "user_no_policies" {
  type        = bool
  default     = true
  description = "Check user no policies."
}


variable "no_policies_with_full_admin_access" {
  type        = bool
  default     = true
  description = "Check user no policies with full admin access."
}

variable "acm_certificate_expiration_check" {
  type        = bool
  default     = true
  description = "Check ACM Certificates in your account are marked for expiration within the specified number of days."
}

variable "acm_days_to_expiration" {
  type        = number
  default     = 14
  description = "Specify the number of days before the rule flags the ACM Certificate as noncompliant."
}

variable "ec2_volume_inuse_check" {
  type        = bool
  default     = true
  description = "Checks whether EBS volumes are attached to EC2 instances."
}

variable "ebs_snapshot_public_restorable" {
  type        = bool
  default     = true
  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable."
}

variable "rds_storage_encrypted" {
  type        = bool
  default     = true
  description = "Checks whether storage encryption is enabled for your RDS DB instances."
}

variable "rds_instance_public_access_check" {
  type        = bool
  default     = true
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible."
}

variable "rds_snapshots_public_prohibited" {
  type        = bool
  default     = true
  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."
}

variable "guardduty_enabled_centralized" {
  type        = bool
  default     = true
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."
}

variable "s3_bucket_public_write_prohibited" {
  type        = bool
  default     = true
  description = "Checks that your S3 buckets do not allow public write access."
}

variable "eip_attached" {
  type        = bool
  default     = true
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."
}

variable "ec2_encrypted_volumes" {
  type        = bool
  default     = true
  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."
}

variable "iam_root_access_key" {
  type        = bool
  default     = true
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist."
}

variable "vpc_default_security_group_closed" {
  type        = bool
  default     = true
  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic."
}

variable "s3_bucket_ssl_requests_only" {
  type        = bool
  default     = true
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."
}

variable "config_cloudtrail_enabled" {
  type        = bool
  default     = true
  description = "Ensuring that the cloudtrail is enabled."
}

variable "multi_region_cloudtrail_enabled" {
  type        = bool
  default     = true
  description = "Ensuring that the multi-region-cloud-trail is enabled"
}

variable "instances_in_vpc" {
  type        = bool
  default     = true
  description = "Ensuring that all the instances in VPC"
}

variable "cloudwatch_log_group_encrypted" {
  type        = bool
  default     = true
  description = "Ensuring that log group is encrypted"
}

variable "iam_password_policy" {
  type        = bool
  default     = true
  description = "Ensuring that log group is encrypted"
}

variable "password_require_uppercase" {
  type        = bool
  default     = true
  description = "Require at least one uppercase character in password."
}

variable "password_require_lowercase" {
  type        = bool
  default     = true
  description = "Require at least one lowercase character in password."
}

variable "password_require_symbols" {
  type        = bool
  default     = true
  description = "Require at least one symbol in password."
}

variable "password_require_numbers" {
  type        = bool
  default     = true
  description = "Require at least one number in password."
}

variable "password_min_length" {
  type        = number
  default     = 14
  description = "Password minimum length."
}

variable "password_reuse_prevention" {
  type        = number
  default     = 24
  description = "Number of passwords before allowing reuse."
}

variable "password_max_age" {
  type        = number
  default     = 90
  description = "Number of days before password expiration."
}
