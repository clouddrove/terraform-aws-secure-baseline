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

variable "Access_keys_rotated" {
  type        = bool
  default     = false
  description = "Maximum number of days without rotation. Default 90."
}

variable "Access_keys_rotated_value" {
  type        = string
  default     = "{\"maxAccessKeyAge\": \"90\"}"
  description = "Number of days default is 90."
}

variable "Account_part_of_organization" {
  type        = bool
  default     = false
  description = "Maximum number of days without rotation. Default 90."
}

variable "alb_http_drop_invalid_header_enabled" {
  type        = bool
  default     = false
  description = "All supported AWS regions except Asia Pacific (Osaka), Europe (Milan), Africa (Cape Town) Region"
}

variable "alb_http_to_https_redirection_check" {
  type        = bool
  default     = false
  description = "Checks if HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers."
}

variable "alb_waf_enabled" {
  type        = bool
  default     = false
  description = "Checks if Web Application Firewall (WAF) is enabled on Application Load Balancers (ALBs). "
}

variable "api_gw_associated_with_waf" {
  type        = bool
  default     = false
  description = "Checks if an Amazon API Gateway API stage is using an AWS WAF Web ACL.  "
}

variable "api_gw_cache_enabled_and_encrypted" {
  type        = bool
  default     = false
  description = "Checks if an Amazon API Gateway API stage is using an AWS WAF Web ACL.  "
}

variable "api_gw_endpoint_type_check" {
  type        = bool
  default     = false
  description = "Checks if Amazon API Gateway APIs are of the type specified in the rule parameter endpointConfigurationType."
}

variable "api_gw_endpoint_type_check_value" {
  type        = string
  default     = "{\"endpointConfigurationTypes\": \"PRIVATE\"}"
  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts."
}

variable "api_gw_execution_logging_enable" {
  type        = bool
  default     = false
  description = "Checks that all methods in Amazon API Gateway stage has logging enabled. "
}

variable "api_gw_ssl_enabled" {
  type        = bool
  default     = false
  description = "Checks if a REST API stage uses an Secure Sockets Layer (SSL) certificate. "
}

variable "api_gw_xray_enabled" {
  type        = bool
  default     = false
  description = "Checks if AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs. "
}

variable "approved_aims_by_id" {
  type        = bool
  default     = false
  description = "Checks if running instances are using specified AMIs. Specify a list of approved AMI IDs.  "
}

variable "approved_aims_by_id_value" {
  type        = string
  default     = "{\"amiIds\": \"ami-0a23ccb2cdd9286bb\"}"
  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts."
}

variable "approved_aims_by_tag" {
  type        = bool
  default     = false
  description = "Checks if running instances are using specified AMIs. Specify a list of approved AMI IDs.  "
}

variable "approved_aims_by_tag_value" {
  type        = string
  default     = "{\"amisByTagKeyAndValue\": \"tag-key:tag-value,other-tag-key\"}"
  description = "Checks if running instances are using specified AMIs. Specify a list of approved AMI IDs.  "
}

variable "aurora_mysql_backtracking_enabled" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Aurora MySQL cluster has backtracking enabled.  "
}

variable "aurora_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon Aurora DB clusters are protected by a backup plan.   "
}

variable "autoscaling_group_elb_healthcheck_required" {
  type        = bool
  default     = false
  description = "Checks whether your Auto Scaling groups that are associated with a load balancer are using Elastic Load Balancing health checks."
}

variable "autoscaling_launch_config_public_ip_disabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations."
}

variable "backup_plan_min_frequency_and_min_retention_check" {
  type        = bool
  default     = false
  description = "Checks if a backup plan has a backup rule that satisfies the required frequency and retention period."
}

variable "backup_recovery_point_encrypted" {
  type        = bool
  default     = false
  description = "Checks if a recovery point is encrypted. "
}

variable "backup_recovery_point_manual_deletion_disabled" {
  type        = bool
  default     = false
  description = "Checks if a backup vault has an attached resource-based policy which prevents deletion of recovery points. "
}

variable "backup_recovery_point_minimum_retention_check" {
  type        = bool
  default     = false
  description = "Checks if a recovery point expires no earlier than after the specified period."
}

variable "cloudtrail_s3_dataevents_enabled" {
  type        = bool
  default     = false
  description = "Checks whether at least one AWS CloudTrail trail is logging Amazon S3 data events for all S3 buckets. "
}

variable "cloudtrail_security_trail_enabled" {
  type        = bool
  default     = false
  description = "Checks that there is at least one AWS CloudTrail trail defined with security best practices. "
}

variable "cloud_trail_cloud_watch_logs_enabled" {
  type        = bool
  default     = false
  description = "Checks whether AWS CloudTrail trails are configured to send logs to Amazon CloudWatch logs. "
}

variable "cloud_trail_enabled" {
  type        = bool
  default     = false
  description = "Checks if AWS CloudTrail is enabled in your AWS account."
}

variable "cloud_trail_encryption_enabled" {
  type        = bool
  default     = false
  description = "Checks if AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service KMS key encryption. "
}

variable "cloud_trail_log_file_validation_enabled" {
  type        = bool
  default     = false
  description = "Checks whether AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. "
}


variable "db_instance_backup_enabled" {
  type        = bool
  default     = false
  description = "Checks if RDS DB instances have backups enabled. Optionally, the rule checks the backup retention period and the backup window."
}

variable "desired_instance_tenancy" {
  type        = bool
  default     = false
  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts."
}

variable "desired_instance_tenancy_value" {
  type        = string
  default     = "{\"tenancy\": \"DEFAULT\"}"
  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts."
}

variable "desired_instance_type" {
  type        = bool
  default     = false
  description = "Checks whether your EC2 instances are of the specified instance types."
}

variable "desired_instance_type_value" {
  type        = string
  default     = "{\"instanceType\": \"t2.small\"}"
  description = "Checks whether your EC2 instances are of the specified instance types."
}

variable "ebs_optimized_instance" {
  type        = bool
  default     = false
  description = "Checks whether EBS optimization is enabled for your EC2 instances that can be EBS-optimized. "
}

variable "ec2_ebs_encryption_by_default" {
  type        = bool
  default     = false
  description = "Check that Amazon Elastic Block Store (EBS) encryption is enabled by default."
}

variable "ec2_instance_detailed_monitoring_enabled" {
  type        = bool
  default     = false
  description = "Checks if detailed monitoring is enabled for EC2 instances."
}

variable "ec2_instance_managed_by_ssm" {
  type        = bool
  default     = false
  description = "Checks whether the Amazon EC2 instances in your account are managed by AWS Systems Manager. "
}

variable "ec2_instance_profile_attached" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Elastic Compute Cloud (Amazon EC2) instance has an Identity and Access Management (IAM) profile attached to it."
}

variable "ec2_stopped_instance" {
  type        = bool
  default     = false
  description = "Checks if there are instances stopped for more than the allowed number of days. "
}

variable "efs_encrypted_check" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic File System (Amazon EFS) is configured to encrypt the file data using AWS Key Management Service (AWS KMS). "
}

variable "eks_endpoint_no_public_access" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible. "
}

variable "eks_secrets_encrypted" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using AWS Key Management Service (KMS) keys."
}

variable "elbv2_acm_certificate_required" {
  type        = bool
  default     = false
  description = "Checks if Application Load Balancers and Network Load Balancers are configured to use certificates from AWS Certificate Manager (ACM). "
}

variable "elb_acm_certificate_required" {
  type        = bool
  default     = false
  description = "Checks if the Classic Load Balancers use SSL certificates provided by AWS Certificate Manager. "
}

variable "elb_custom_security_policy_ssl_check" {
  type        = bool
  default     = false
  description = "Checks whether your Classic Load Balancer SSL listeners are using a custom policy.  "
}

variable "elb_custom_security_policy_ssl_check_value" {
  type        = string
  default     = "{\"sslProtocolsAndCiphers\": \"ssh\"}"
  description = "Checks if for each IAM resource, a policy ARN in the input parameter is attached to the IAM resource.  "
}

variable "elb_deletion_protection_enabled" {
  type        = bool
  default     = false
  description = "Checks if Elastic Load Balancing has deletion protection enabled. "
}

variable "elb_logging_enabled" {
  type        = bool
  default     = false
  description = "Checks if the Application Load Balancer and the Classic Load Balancer have logging enabled."
}

variable "elb_tls_https_listeners_only" {
  type        = bool
  default     = false
  description = "Checks if your Classic Load Balancer is configured with SSL or HTTPS listeners."
}

variable "encrypted_volumes" {
  type        = bool
  default     = false
  description = "Checks if the EBS volumes that are in an attached state are encrypted. "
}

variable "guardduty_non_archived_findings" {
  type        = bool
  default     = false
  description = "Checks whether Amazon GuardDuty has findings that are non archived.  "
}

variable "iam_no_inline_policy_check" {
  type        = bool
  default     = false
  description = "Checks that inline policy feature is not in use.   "
}

variable "iam_policy_blacklisted_check" {
  type        = bool
  default     = false
  description = "Checks if for each IAM resource, a policy ARN in the input parameter is attached to the IAM resource.  "
}

variable "iam_policy_blacklisted_check_value" {
  type        = string
  default     = "{\"policyArns\": \"arn:aws:iam::aws:policy/AdministratorAccess\"}"
  description = "Checks if for each IAM resource, a policy ARN in the input parameter is attached to the IAM resource.  "
}

variable "iam_policy_in_use" {
  type        = bool
  default     = false
  description = "Checks if for each IAM resource, a policy ARN in the input parameter is attached to the IAM resource.  "
}

variable "iam_policy_in_use_arn" {
  type        = string
  default     = "{\"policyARN\": \"arn:aws:iam::aws:policy/AWSAccountManagementReadOnlyAccess\"}"
  description = "Provides read-only access to AWS Account Management"
}

variable "iam_user_mfa_enabled" {
  type        = bool
  default     = false
  description = "Checks whether the AWS Identity and Access Management users have multi-factor authentication (MFA)"
}

variable "incoming_ssh_disabled" {
  type        = bool
  default     = false
  description = "Checks if the incoming SSH traffic for the security groups is accessible. "
}

variable "internet_gateway_authorized_vpc_only" {
  type        = bool
  default     = false
  description = "Checks that Internet gateways (IGWs) are only attached to an authorized Amazon Virtual Private Cloud (VPCs).  "
}

variable "lambda_concurrency_check" {
  type        = bool
  default     = false
  description = "Checks whether the AWS Lambda function is configured with function-level concurrent execution limit."
}

variable "lambda_dlq_check" {
  type        = bool
  default     = false
  description = "Checks whether an AWS Lambda function is configured with a dead-letter queue."
}

variable "lambda_function_public_access_prohibited" {
  type        = bool
  default     = false
  description = "Checks if the AWS Lambda function policy attached to the Lambda resource prohibits public access. "
}

variable "lambda_function_settings_check" {
  type        = bool
  default     = false
  description = "Checks that the AWS Lambda function settings for runtime, role, timeout, and memory size match the expected values. "
}

variable "lambda_function_settings_check_value" {
  type        = string
  default     = "{\"runtime\": \"Python 3.9\"}"
  description = "Checks instances for specified tenancy. Specify AMI IDs to check instances that are launched from those AMIs or specify host IDs to check whether instances are launched on those Dedicated Hosts."
}

variable "lambda_inside_vpc" {
  type        = bool
  default     = false
  description = "Checks whether an AWS Lambda function is allowed access to an Amazon Virtual Private Cloud. I"
}

variable "mfa_enabled_for_iam_console_access" {
  type        = bool
  default     = false
  description = "Checks whether AWS Multi-Factor Authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password."
}

variable "no_unrestricted_route_to_igw" {
  type        = bool
  default     = false
  description = "Checks if there are public routes in the route table to an Internet Gateway (IGW). "
}

variable "rds_automatic_minor_version_upgrade_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon Relational Database Service (RDS) database instances are configured for automatic minor version upgrades. "
}

variable "rds_cluster_deletion_protection_enabled" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled."
}

variable "rds_cluster_iam_authentication_enabled" {
  type        = bool
  default     = false
  description = "Checks if an Amazon RDS Cluster has AWS Identity and Access Management (IAM) authentication enabled."
}

variable "rds_cluster_multi_az_enabled" {
  type        = bool
  default     = false
  description = "Checks if Multi-AZ replication is enabled on Amazon Aurora clusters managed by Amazon Relational Database Service (Amazon RDS). "
}

variable "rds_enhanced_monitoring_enabled" {
  type        = bool
  default     = false
  description = "Checks whether enhanced monitoring is enabled for Amazon Relational Database Service (Amazon RDS) instances."
}

variable "rds_instance_deletion_protection_enabled" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled."
}

variable "rds_instance_iam_authentication_enabled" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM) authentication enabled. "
}

variable "rds_logging_enabled" {
  type        = bool
  default     = false
  description = "Checks if log types exported to Amazon CloudWatch for an Amazon Relational Database Service (Amazon RDS) instance are enabled."
}

variable "rds_multi_az_support" {
  type        = bool
  default     = false
  description = "Checks whether high availability is enabled for your RDS DB instances.yes"
}

variable "rds_snapshot_encrypted" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. "
}

variable "root_account_mfa_enabled" {
  type        = bool
  default     = false
  description = "Checks whether the root user of your AWS account requires multi-factor authentication for console sign-in."
}

variable "s3_bucket_logging_enabled" {
  type        = bool
  default     = false
  description = "Checks whether logging is enabled for your S3 buckets."
}

variable "s3_bucket_server_side_encryption_enabled" {
  type        = bool
  default     = false
  description = "Checks that your Amazon S3 bucket either has Amazon S3 default encryption enabled or that the S3 bucket policy explicitly denies put-object requests without server side encryption that uses AES-256 or AWS Key Management Service."
}

variable "s3_bucket_versioning_enabled" {
  type        = bool
  default     = false
  description = "Checks if versioning is enabled for your S3 buckets. "
}

variable "s3_default_encryption_kms" {
  type        = bool
  default     = false
  description = "Checks whether the Amazon S3 buckets are encrypted with AWS Key Management Service(AWS KMS). "
}

variable "secretsmanager_secret_unused" {
  type        = bool
  default     = false
  description = "Checks if AWS Secrets Manager secrets have been accessed within a specified number of days. "
}

variable "sns_encrypted_kms" {
  type        = bool
  default     = false
  description = "Checks if Amazon SNS topic is encrypted with AWS Key Management Service (AWS KMS).  "
}

variable "vpc_flow_logs_enabled" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Virtual Private Cloud flow logs are found and enabled for Amazon VPC."
}

variable "wafv2_logging_enabled" {
  type        = bool
  default     = false
  description = "Checks whether logging is enabled on AWS Web Application Firewall (WAFV2) regional and global web access control list (ACLs). "
}

variable "beanstalk_enhanced_health_reporting_enabled" {
  type        = bool
  default     = false
  description = "Checks if an AWS Elastic Beanstalk environment is configured for enhanced health reporting. "
}

variable "cloudfront_accesslogs_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon CloudFront distributions are configured to capture information from Amazon Simple Storage Service (Amazon S3) server access logs. "
}

variable "cloudfront_associated_with_waf" {
  type        = bool
  default     = false
  description = "Checks if Amazon CloudFront distributions are associated with either WAF or WAFv2 web access control lists (ACLs). "
}

variable "cloudfront_custom_ssl_certificate" {
  type        = bool
  default     = false
  description = "Checks if the certificate associated with an Amazon CloudFront distribution is the default Secure Sockets Layer (SSL) certificate.  "
}

variable "cloudfront_default_root_object_configured" {
  type        = bool
  default     = false
  description = "Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root object.  "
}

variable "cloudfront_origin_access_identity_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon CloudFront distribution with S3 Origin type has Origin Access Identity (OAI) configured. "
}

variable "cloudfront_origin_failover_enabled" {
  type        = bool
  default     = false
  description = "Checks whether an origin group is configured for the distribution of at least 2 origins in the origin group for Amazon CloudFront. "
}

variable "cloudfront_sni_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests.  "
}

variable "cloudfront_viewer_policy_https" {
  type        = bool
  default     = false
  description = "Checks whether your Amazon CloudFront distributions use HTTPS (directly or via a redirection).  "
}

variable "cloudwatch_alarm_action_check" {
  type        = bool
  default     = false
  description = "Checks whether CloudWatch alarms have at least one alarm action, one INSUFFICIENT_DATA action, or one OK action enabled.   "
}


variable "cloudwatch_alarm_action_check_value" {
  type        = string
  default     = "{\"alarmActionRequired\": \"true\", \"insufficientDataActionRequired\": \"true\",\"okActionRequired\": \"false\"}"
  description = "Checks whether CloudWatch alarms have at least one alarm action, one INSUFFICIENT_DATA action, or one OK action enabled.  "
}

variable "cloudwatch_alarm_resource_check" {
  type        = bool
  default     = false
  description = "Checks whether the specified resource type has a CloudWatch alarm for the specified metric. "
}

variable "cloudwatch_alarm_resource_check_value" {
  type        = string
  default     = "{\"resourceType\": \"AWS::EC2::Instance\", \"metricName\": \"CPUUtilization\"}"
  description = "Checks whether the specified resource type has a CloudWatch alarm for the specified metric."
}

variable "cloudwatch_alarm_settings_check" {
  type        = bool
  default     = false
  description = "Checks whether CloudWatch alarms with the given metric name have the specified settings. "
}

variable "cloudwatch_alarm_settings_check_value" {
  type        = string
  default     = "{\"metricName\": \"CPUUtilization\"}"
  description = "Checks whether the specified resource type has a CloudWatch alarm for the specified metric."
}

variable "cmk_backing_key_rotation_enabled" {
  type        = bool
  default     = false
  description = "Checks if key rotation is enabled for each key and matches to the key ID of the customer created AWS KMS key (KMS key). "
}

variable "codebuild_project_envvar_awscred_check" {
  type        = bool
  default     = false
  description = "Checks whether the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. "
}

variable "codebuild_project_source_repo_url_check" {
  type        = bool
  default     = false
  description = "Checks whether the GitHub or Bitbucket source repository URL contains either personal access tokens or user name and password.  "
}

variable "codepipeline_deployment_count_check" {
  type        = bool
  default     = false
  description = "Checks whether the first deployment stage of the AWS Codepipeline performs more than one deployment."
}

variable "codepipeline_region_fanout_check" {
  type        = bool
  default     = false
  description = "Checks if each stage in the AWS CodePipeline deploys to more than N times "
}

variable "cw_loggroup_retention_period_check" {
  type        = bool
  default     = false
  description = "Checks whether Amazon CloudWatch LogGroup retention period is set to specific number of days.  "
}

variable "dax_encryption_enabled" {
  type        = bool
  default     = false
  description = "Checks that Amazon DynamoDB Accelerator (DAX) clusters are encrypted.  "
}

variable "dms_replication_not_public" {
  type        = bool
  default     = false
  description = "Checks whether AWS Database Migration Service replication instances are public.  "
}

variable "dynamodb_autoscaling_enabled" {
  type        = bool
  default     = false
  description = "Checks if Auto Scaling or On-Demand is enabled on your DynamoDB tables and/or global secondary indexes. "
}

variable "dynamodb_in_backup_plan" {
  type        = bool
  default     = false
  description = "Checks whether Amazon DynamoDB table is present in AWS Backup Plans.  "
}

variable "dynamodb_pitr_enabled" {
  type        = bool
  default     = false
  description = "Checks that point in time recovery (PITR) is enabled for Amazon DynamoDB tables. T "
}


variable "dynamodb_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon DynamoDB tables are protected by a backup plan.  "
}

variable "dynamodb_table_encrypted_kms" {
  type        = bool
  default     = false
  description = "Checks if Amazon DynamoDB table is encrypted with AWS Key Management Service (KMS).   "
}

variable "dynamodb_table_encryption_enabled" {
  type        = bool
  default     = false
  description = "Checks if the Amazon DynamoDB tables are encrypted and checks their status.   "
}


variable "dynamodb_throughput_limit_check" {
  type        = bool
  default     = false
  description = "Checks if provisioned DynamoDB throughput is approaching the maximum limit for your account."
}


variable "ebs_in_backup_plan" {
  type        = bool
  default     = false
  description = "Check if Amazon Elastic Block Store (Amazon EBS) volumes are added in backup plans of AWS Backup."
}

variable "ebs_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic Block Store (Amazon EBS) volumes are protected by a backup plan. "
}

variable "ec2_imdsv2_check" {
  type        = bool
  default     = false
  description = "Checks whether your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). "
}

variable "ec2_instance_multiple_eni_check" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic Compute Cloud (Amazon EC2) uses multiple ENIs (Elastic Network Interfaces) or Elastic Fabric Adapters (EFAs).  "
}


variable "ec2_instance_no_public_ip" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Elastic Compute Cloud (Amazon EC2) instances have a public IP association. "
}

variable "ec2_managedinstance_applications_blacklisted" {
  type        = bool
  default     = false
  description = "Checks that none of the specified applications are installed on the instance.  "
}

variable "ec2_managedinstance_applications_blacklisted_value" {
  type        = string
  default     = "{\"applicationNames\": \"Firefox\"}"
  description = "Checks that none of the specified applications are installed on the instance.  "
}

variable "ec2_managedinstance_applications_required" {
  type        = bool
  default     = false
  description = "Checks if all of the specified applications are installed on the instance.  "
}

variable "ec2_managedinstance_applications_required_value" {
  type        = string
  default     = "{\"applicationNames\": \"Firefox\"}"
  description = "Checks that none of the specified applications are installed on the instance.  "
}

variable "ec2_managedinstance_association_compliance_status_check" {
  type        = bool
  default     = false
  description = "Checks if the status of the AWS Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. "
}

variable "ec2_managedinstance_inventory_blacklisted" {
  type        = bool
  default     = false
  description = "Checks whether instances managed by Amazon EC2 Systems Manager are configured to collect blacklisted inventory types."
}

variable "ec2_managedinstance_inventory_blacklisted_value" {
  type        = string
  default     = "{\"inventoryNames\": \"AWS:Network\"}"
  description = "Checks whether instances managed by Amazon EC2 Systems Manager are configured to collect blacklisted inventory types."
}

variable "ec2_managedinstance_patch_compliance_status_check" {
  type        = bool
  default     = false
  description = "Checks whether the compliance status of the AWS Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance."
}

variable "ec2_managedinstance_platform_check" {
  type        = bool
  default     = false
  description = " Checks whether EC2 managed instances have the desired configurations."
}

variable "ec2_managedinstance_platform_check_value" {
  type        = string
  default     = "{\"platformType\": \"Linux\"}"
  description = " Checks whether EC2 managed instances have the desired configurations."
}

variable "ec2_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are protected by a backup plan. "
}

variable "ec2_security_group_attached_to_eni" {
  type        = bool
  default     = false
  description = "Checks that non-default security groups are attached to Amazon Elastic Compute Cloud (EC2) instances or an elastic network interfaces (ENIs).  "
}

variable "ecs_task_definition_user_for_host_mode_check" {
  type        = bool
  default     = false
  description = "Checks if an Amazon Elastic Container Service (Amazon ECS) task definition with host networking mode has 'privileged' or 'user' container definitions. "
}

variable "efs_in_backup_plan" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. "
}

variable "efs_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. "
}

variable "elasticache_redis_cluster_automatic_backup_check" {
  type        = bool
  default     = false
  description = "Check if the Amazon ElastiCache Redis clusters have automatic backup turned on."
}

variable "elasticsearch_encrypted_at_rest" {
  type        = bool
  default     = false
  description = "Checks if Amazon OpenSearch Service (OpenSearch Service) domains have encryption at rest configuration enabled."
}


variable "elasticsearch_logs_to_cloudwatch" {
  type        = bool
  default     = false
  description = "Checks if Amazon OpenSearch Service (OpenSearch Service) domains are configured to send logs to Amazon CloudWatch Logs. "
}

variable "elasticsearch_node_to_node_encryption_check" {
  type        = bool
  default     = false
  description = "Check that Amazon OpenSearch Service nodes are encrypted end to end. "
}


variable "elastic_beanstalk_managed_updates_enabled" {
  type        = bool
  default     = false
  description = "Checks if managed platform updates in an AWS Elastic Beanstalk environment is enabled.  "
}


variable "elb_cross_zone_load_balancing_enabled" {
  type        = bool
  default     = false
  description = "Checks if cross-zone load balancing is enabled for the Classic Load Balancers (CLBs). "
}

variable "elb_predefined_security_policy_ssl_check" {
  type        = bool
  default     = false
  description = "Checks whether your Classic Load Balancer SSL listeners are using a predefined policy. "
}

variable "elb_predefined_security_policy_ssl_check_value" {
  type        = string
  default     = "{\"predefinedPolicyName\": \"default\"}"
  description = "Checks whether your Classic Load Balancer SSL listeners are using a predefined policy. "
}

variable "emr_kerberos_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon EMR clusters have Kerberos enabled.  "
}

variable "emr_master_no_public_ip" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. "
}

variable "fms_shield_resource_policy_check" {
  type        = bool
  default     = false
  description = "Checks if Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. "
}

variable "fms_shield_resource_policy_check_value" {
  type        = string
  default     = "{\"webACLId\": \"default\", \"resourceTypes\": \"t2.micro\"}"
  description = "Checks if Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. "
}

variable "fms_webacl_resource_policy_check" {
  type        = bool
  default     = false
  description = "Checks if the web ACL is associated with an Application Load Balancer, API Gateway stage, or Amazon CloudFront distributions. "
}

variable "fms_webacl_resource_policy_check_value" {
  type        = string
  default     = "{\"webACLId\": \"default\"}"
  description = "Checks if Amazon Elastic MapReduce (EMR) clusters' master nodes have public IPs. "
}

variable "fms_webacl_rulegroup_association_check" {
  type        = bool
  default     = false
  description = "Checks if the rule groups associate with the web ACL at the correct priority. "
}

variable "fms_webacl_rulegroup_association_check_value" {
  type        = string
  default     = "{\"ruleGroups\": \"ruleGroupId-1:NONE\"}"
  description = "Checks if the rule groups associate with the web ACL at the correct priority. "
}

variable "fsx_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon FSx File Systems are protected by a backup plan.  "
}

variable "iam_customer_policy_blocked_kms_actions" {
  type        = bool
  default     = false
  description = "Checks that the managed AWS Identity and Access Management (IAM) policies that you create do not allow blocked actions on all AWS KMS keys. "
}

variable "iam_customer_policy_blocked_kms_actions_value" {
  type        = string
  default     = "{\"blockedActionsPatterns\": \"kms:*\"}"
  description = "Checks that the managed AWS Identity and Access Management (IAM) policies that you create do not allow blocked actions on all AWS KMS keys. "
}

variable "iam_group_has_users_check" {
  type        = bool
  default     = false
  description = "Checks whether IAM groups have at least one IAM user."
}

variable "iam_inline_policy_blocked_kms_actions" {
  type        = bool
  default     = false
  description = "Checks that the inline policies attached to your IAM users, roles, and groups do not allow blocked actions on all AWS Key Management Service (KMS) keys. "
}

variable "iam_inline_policy_blocked_kms_actions_value" {
  type        = string
  default     = "{\"blockedActionsPatterns\": \"kms:*\"}"
  description = "Checks that the inline policies attached to your IAM users, roles, and groups do not allow blocked actions on all AWS Key Management Service (KMS) keys. "
}

variable "iam_policy_no_statements_with_full_access" {
  type        = bool
  default     = false
  description = "Checks if AWS Identity and Access Management (IAM) policies grant permissions to all actions on individual AWS resources."
}

variable "iam_role_managed_policy_check" {
  type        = bool
  default     = false
  description = "Checks that the AWS Identity and Access Management (IAM) role is attached to all AWS managed policies specified in the list of managed policies. "
}

variable "iam_role_managed_policy_check_value" {
  type        = string
  default     = "{\"managedPolicyArns\": \"arn:aws:iam::aws:policy/AWSAccountManagementReadOnlyAccess:*\"}"
  description = "Checks that the AWS Identity and Access Management (IAM) role is attached to all AWS managed policies specified in the list of managed policies. "
}

variable "iam_user_group_membership_check" {
  type        = bool
  default     = false
  description = "Checks whether IAM users are members of at least one IAM group."
}

variable "kms_cmk_not_scheduled_for_deletion" {
  type        = bool
  default     = false
  description = "Checks if AWS KMS keys (KMS keys) are not scheduled for deletion in AWS Key Management Service (AWS KMS)."
}

variable "rds_in_backup_plan" {
  type        = bool
  default     = false
  description = "Checks whether Amazon RDS database is present in back plans of AWS Backup. "
}

variable "rds_resources_protected_by_backup_plan" {
  type        = bool
  default     = false
  description = "Checks if Amazon Relational Database Service (Amazon RDS) instances are protected by a backup plan. "
}

variable "redshift_backup_enabled" {
  type        = bool
  default     = false
  description = "Checks that Amazon Redshift automated snapshots are enabled for clusters.  "
}

variable "redshift_cluster_configuration_check" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Redshift clusters have the specified settings."
}

variable "redshift_cluster_configuration_check_value" {
  type        = string
  default     = "{\"clusterDbEncrypted\": \"true\", \"loggingEnabled\": \"true\"}"
  description = "Checks whether Amazon Redshift clusters have the specified settings."
}

variable "redshift_cluster_kms_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon Redshift clusters are using a specified AWS Key Management Service (AWS KMS) key for encryption. "
}

variable "redshift_cluster_maintenancesettings_check" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Redshift clusters have the specified maintenance settings."
}

variable "redshift_cluster_maintenancesettings_check_value" {
  type        = string
  default     = "{\"allowVersionUpgrade\": \"true\"}"
  description = "Checks whether Amazon Redshift clusters have the specified maintenance settings."
}

variable "redshift_cluster_public_access_check" {
  type        = bool
  default     = false
  description = "Checks if Amazon Redshift clusters are not publicly accessible."
}

variable "redshift_enhanced_vpc_routing_enabled" {
  type        = bool
  default     = false
  description = "Checks if Amazon Redshift cluster has 'enhancedVpcRouting' enabled. "
}

variable "redshift_require_tls_ssl" {
  type        = bool
  default     = false
  description = "Checks whether Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients."
}

variable "required_tags" {
  type        = bool
  default     = false
  description = "Checks if your resources have the tags that you specify."
}

variable "required_tags_value" {
  type        = string
  default     = "{\"tag1Key\": \"CostCenter\"}"
  description = "Checks if your resources have the tags that you specify."
}

variable "restricted-common-ports" {
  type        = bool
  default     = false
  description = "Checks if the security groups in use do not allow unrestricted incoming TCP traffic to the specified ports."
}

variable "root_account_hardware_mfa_enabled" {
  type        = bool
  default     = false
  description = "Checks if your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root credentials."
}

variable "s3_account_level_public_access_blocks" {
  type        = bool
  default     = false
  description = "Checks if the required public access block settings are configured from account level. "
}

variable "s3_account_level_public_access_blocks_periodic" {
  type        = bool
  default     = false
  description = "Checks if the required public access block settings are configured from account level."
}

variable "s3_bucket_blacklisted_actions_prohibited" {
  type        = bool
  default     = false
  description = "Checks if the Amazon Simple Storage Service bucket policy does not allow blacklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts."
}

variable "s3_bucket_blacklisted_actions_prohibited_value" {
  type        = string
  default     = "{\"blacklistedActionPattern\": \"s3:GetBucket*\"}"
  description = "Checks if the Amazon Simple Storage Service bucket policy does not allow blacklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts."
}

variable "s3_bucket_default_lock_enabled" {
  type        = bool
  default     = false
  description = "Checks whether Amazon S3 bucket has lock enabled, by default. "
}

variable "s3_bucket_level_public_access_prohibited" {
  type        = bool
  default     = false
  description = "Checks if Amazon Simple Storage Service (Amazon S3) buckets are publicly accessible.  "
}

variable "s3_bucket_policy_grantee_check" {
  type        = bool
  default     = false
  description = "Checks that the access granted by the Amazon S3 bucket is restricted by any of the AWS principals, federated users, service principals, IP addresses, or VPCs that you provide.   "
}

variable "s3_bucket_policy_not_more_permissive" {
  type        = bool
  default     = false
  description = "Checks if your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide. "
}

variable "s3_bucket_policy_not_more_permissive_value" {
  type        = string
  default     = "{\"controlPolicy\": \"arn:aws:iam::aws:policy/AWSAccountManagementReadOnlyAccess\"}"
  description = "Checks if your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide. "
}

variable "s3_bucket_public_read_prohibited" {
  type        = bool
  default     = false
  description = "Checks if your Amazon S3 buckets do not allow public read access. "
}

variable "s3_bucket_replication_enabled" {
  type        = bool
  default     = false
  description = "Checks whether the Amazon S3 buckets have cross-region replication enabled."
}

variable "sagemaker_endpoint_configuration_kms_key_configured" {
  type        = bool
  default     = false
  description = "Checks whether AWS Key Management Service (KMS) key is configured for an Amazon SageMaker endpoint configuration. "
}

variable "sagemaker_notebook_instance_kms_key_configured" {
  type        = bool
  default     = false
  description = "Check whether an AWS Key Management Service (KMS) key is configured for an Amazon SageMaker notebook instance."
}

variable "sagemaker_notebook_no_direct_internet_access" {
  type        = bool
  default     = false
  description = "Checks whether direct internet access is disabled for an Amazon SageMaker notebook instance. "
}

variable "secretsmanager_rotation_enabled_check" {
  type        = bool
  default     = false
  description = "Checks if AWS Secrets Manager secret has rotation enabled.  "
}

variable "secretsmanager_scheduled_rotation_success_check" {
  type        = bool
  default     = false
  description = "Checks whether AWS Secrets Manager secret rotation has triggered/started successfully as per the rotation schedule.  "
}

variable "secretsmanager_secret_periodic_rotation" {
  type        = bool
  default     = false
  description = "Checks if AWS Secrets Manager secrets have been rotated in the past specified number of days. "
}

variable "secretsmanager_using_cmk" {
  type        = bool
  default     = false
  description = "Checks if all secrets in AWS Secrets Manager are encrypted using the AWS managed key (aws/secretsmanager) or a customer managed key that you created in AWS Key Management Service (AWS KMS). "
}

variable "securityhub_enabled" {
  type        = bool
  default     = false
  description = "Checks that AWS Security Hub is enabled for an AWS Account.  "
}

variable "service_vpc_endpoint_enabled" {
  type        = bool
  default     = false
  description = "Checks whether Service Endpoint for the service provided in rule parameter is created for each Amazon VPC. "
}

variable "service_vpc_endpoint_enabled_value" {
  type        = string
  default     = "{\"serviceName\": \"DescribeVpcEndpointServices\"}"
  description = "Checks whether Service Endpoint for the service provided in rule parameter is created for each Amazon VPC. "
}

variable "shield_advanced_enabled_autorenew" {
  type        = bool
  default     = false
  description = "Checks if AWS Shield Advanced is enabled in your AWS account and this subscription is set to automatically renew."
}

variable "shield_drt_access" {
  type        = bool
  default     = false
  description = "Checks if the Shield Response Team (SRT) can access your AWS account. "
}

variable "ssm_document_not_public" {
  type        = bool
  default     = false
  description = "Checks if AWS Systems Manager documents owned by the account are public. "
}

variable "subnet_auto_assign_public_ip_disabled" {
  type        = bool
  default     = false
  description = "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"
}

variable "vpc_network_acl_unused_check" {
  type        = bool
  default     = false
  description = "Checks if there are unused network access control lists (network ACLs)."
}


variable "vpc_sg_open_only_to_authorized_ports" {
  type        = bool
  default     = false
  description = "Checks whether any security groups with inbound 0.0.0.0/0 have TCP or UDP ports accessible. "
}

variable "vpc_vpn_2_tunnels_up" {
  type        = bool
  default     = false
  description = "Checks that both VPN tunnels provided by AWS Site-to-Site VPN are in UP status. "
}

variable "waf_classic_logging_enabled" {
  type        = bool
  default     = false
  description = "Checks if logging is enabled on AWS Web Application Firewall (WAF) classic global web ACLs. "
}

variable "cloudformation_stack_drift_detection_check" {
  type        = bool
  default     = false
  description = "Checks whether your CloudFormation stacks' actual configuration differs, or has drifted, from its expected configuration."
}

variable "cloudformation_stack_drift_detection_check_value" {
  type        = string
  default     = "{\"cloudformationRoleArn\": \"arn:aws:iam::aws:policy/AWSAccountManagementReadOnlyAccess\"}"
  description = "Checks whether your CloudFormation stacks' actual configuration differs, or has drifted, from its expected configuration."
}

variable "cloudformation_stack_notification_check" {
  type        = bool
  default     = false
  description = "Checks whether your CloudFormation stacks are sending event notifications to an SNS topic. Optionally checks whether specified SNS topics are used."
}

variable "elasticsearch_in_vpc_only" {
  type        = bool
  default     = false
  description = "Checks if Amazon OpenSearch Service (OpenSearch Service) domains are in Amazon Virtual Private Cloud (Amazon VPC)."
}


variable "reliability_pillar" {
  type        = bool
  default     = true
  description = "To enable Reliability Pillar Group"
}

variable "security_pillar" {
  type        = bool
  default     = true
  description = "To enable security pillar Group"
}

variable "target_config_prefix" {
  type        = string
  default     = ""
  description = "To specify a key prefix for log objects."
}

variable "target_config_bucket" {
  type        = string
  default     = ""
  description = "To specify a bucket for log objects."
}

variable "sse_algorithm" {
  type        = string
  default     = "AES256"
  description = "The server-side encryption algorithm to use. Valid values are AES256 and aws:kms."
}