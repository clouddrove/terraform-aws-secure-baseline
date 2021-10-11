## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention
module "labels" {
  source = "git::https://github.com/clouddrove/terraform-labels.git?ref=tags/0.12.0"

  name        = var.name
  application = var.application
  environment = var.environment
  label_order = var.label_order
  managedby   = var.managedby

}

resource "null_resource" "cluster" {
  count = var.enabled ? 1 : 0
  provisioner "local-exec" {
    command = format("cd %s/slack && bash build.sh", path.module)
  }
}

data "template_file" "aws_config_acm_certificate_expiration" {
  template = file(
    "${path.module}/policies/acm-certificate-expiration.tpl"
  )

  vars = {
    acm_days_to_expiration = var.acm_days_to_expiration
  }
}

module "config_lambda" {
  source = "git::https://github.com/clouddrove/terraform-aws-lambda.git?ref=tags/0.12.5"

  name        = "config-lambda"
  application = var.application
  environment = var.environment
  label_order = var.label_order
  managedby   = var.managedby
  enabled     = var.enabled

  filename = format("%s/slack/src", path.module)
  handler  = "index.lambda_handler"
  runtime  = "python3.8"
  iam_actions = [
    "logs:CreateLogStream",
    "logs:CreateLogGroup",
    "logs:PutLogEvents",
    "sns:ListTopics",
  ]
  timeout = 30

  names = [
    "python_layer"
  ]
  layer_filenames = [format("%s/slack/packages/Python3-slack.zip", path.module)]
  compatible_runtimes = [
    ["python3.8"]
  ]

  statement_ids = [
    "AllowExecutionFromSNS"
  ]
  actions = [
    "lambda:InvokeFunction"
  ]
  principals = [
    "sns.amazonaws.com"
  ]
  source_arns = [module.sns.topic-arn]
  variables   = var.variables
}

#Module      : SNS
#Description : Provides an SNS topic resource
module "sns" {
  source = "git::https://github.com/clouddrove/terraform-aws-sns.git?ref=tags/0.12.2"

  name         = "alarm-sns"
  application  = var.application
  environment  = var.environment
  label_order  = var.label_order
  managedby    = var.managedby
  enable_topic = true
  enabled      = var.enabled

  protocol        = "lambda"
  endpoint        = module.config_lambda.arn
  delivery_policy = format("%s/_json/delivery_policy.json", path.module)
}

# Module      : S3 BUCKET
# Description : Terraform module to create default S3 bucket with logging and encryption
#               type specific features.
module "s3_bucket" {
  source = "git::https://github.com/clouddrove/terraform-aws-s3.git?ref=tags/0.12.7"

  name        = var.config_s3_bucket_name
  application = var.application
  environment = var.environment
  managedby   = var.managedby
  label_order = ["name"]

  bucket_enabled          = var.enabled
  versioning              = true
  acl                     = "log-delivery-write"
  bucket_policy           = true
  aws_iam_policy_document = data.aws_iam_policy_document.default.json
  force_destroy           = true
}


data "aws_iam_policy_document" "default" {
  statement {
    sid = "AWSConfigBucketPermissionsCheck"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      format("arn:aws:s3:::%s", var.config_s3_bucket_name),
    ]
  }

  statement {
    sid = "AWSConfigBucketExistenceCheck"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:ListBucket",
    ]

    resources = [
      format("arn:aws:s3:::%s", var.config_s3_bucket_name),
    ]
  }

  statement {
    sid = "AWSConfigBucketDelivery"

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      format("arn:aws:s3:::%s/AWSLogs/%s/Config/*", var.config_s3_bucket_name, data.aws_caller_identity.current.account_id),
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}

data "aws_iam_policy_document" "recorder_assume_role_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
}

#Module      : AWS_IAM_ROLE
#Description : Provides an IAM role.
resource "aws_iam_role" "recorder" {
  count              = var.enabled ? 1 : 0
  name               = format("%s-recorder", module.labels.id)
  assume_role_policy = data.aws_iam_policy_document.recorder_assume_role_policy.json

  tags = module.labels.tags
}

# See https://docs.aws.amazon.com/config/latest/developerguide/iamrole-permissions.html
data "aws_iam_policy_document" "recorder_publish_policy" {
  statement {
    actions = ["s3:PutObject"]
    resources = [
      format("arn:aws:s3:::%s%s%s/config/AWSLogs/%s/*", var.config_s3_bucket_name, var.delimiter, var.application, data.aws_caller_identity.current.account_id),
    ]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [format("arn:aws:s3:::%s%s%s", var.config_s3_bucket_name, var.delimiter, var.application)]
  }

  statement {
    actions = ["sns:Publish"]

    resources = [module.sns.topic-arn]
  }
}

#Module      : AWS_IAM_ROLE
#Description : Provides an IAM role policy
resource "aws_iam_role_policy" "recorder_publish_policy" {
  count = var.enabled ? 1 : 0

  name   = format("%s-recorder_publish_policy", module.labels.id)
  role   = join("", aws_iam_role.recorder.*.id)
  policy = data.aws_iam_policy_document.recorder_publish_policy.json
}

#Module      : AWS_IAM_POLICY_ATTACHMENT
#Description : Provides an IAM role policy attachment.
resource "aws_iam_role_policy_attachment" "recorder_read_policy" {
  count = var.enabled ? 1 : 0

  role       = join("", aws_iam_role.recorder.*.id)
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

#Module      : AWS CONFIG CONFIGURATION
#Description : Manages status (recording / stopped) of an AWS Config Configuration Recorder.
resource "aws_config_configuration_recorder_status" "recorder" {
  count = var.enabled ? 1 : 0

  name       = join("", aws_config_configuration_recorder.recorder.*.id)
  is_enabled = var.enabled
  depends_on = [aws_config_delivery_channel.bucket]
}

#Module      : AWS CONFIG CONFIGURATION RECORDER
#Description : Provides an AWS Config Configuration Recorder. Please note that this resource does not start the created recorder automatically.
resource "aws_config_configuration_recorder" "recorder" {
  count = var.enabled ? 1 : 0

  name     = format("%s-recorder", module.labels.id)
  role_arn = join("", aws_iam_role.recorder.*.arn)

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.include_global_resource_types
  }
}

#Module      : AWS CONFIG DELIVERY CHANNEL
#Description : Provides an AWS Config Delivery Channel.
resource "aws_config_delivery_channel" "bucket" {
  count = var.enabled ? 1 : 0

  name           = format("%s-delivery-channel", module.labels.id)
  s3_bucket_name = module.s3_bucket.id
  sns_topic_arn  = module.sns.topic-arn

  snapshot_delivery_properties {
    delivery_frequency = var.delivery_frequency
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

#Module      : AWS CONFIG RUE
#Description : Provides an AWS Config Rule.
resource "aws_config_config_rule" "restricted_ports" {
  count = var.enabled && var.restricted_ports ? 1 : 0

  name = "RestrictedIncomingTraffic"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  input_parameters = var.restricted_ports_list

  tags       = module.labels.tags
  depends_on = [aws_config_configuration_recorder.recorder]

}

#Module      : AWS CONFIG RUE
#Description : Provides an AWS Config Rule.
resource "aws_config_config_rule" "iam_mfa" {
  count = var.enabled && (var.iam_mfa || var.security_pillar) ? 1 : 0

  name = "IAMAccountMFAEnabled"
  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  tags       = module.labels.tags
  depends_on = [aws_config_configuration_recorder.recorder]
}

#Module      : AWS CONFIG RUE
#Description : Provides an AWS Config Rule.
resource "aws_config_config_rule" "unused_credentials" {
  count = var.enabled && (var.unused_credentials || var.security_pillar) ? 1 : 0

  name = "UnusedCredentialsNotExist"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_UNUSED_CREDENTIALS_CHECK"
  }
  input_parameters = "{\"maxCredentialUsageAge\": \"90\"}"
  tags             = module.labels.tags
  depends_on       = [aws_config_configuration_recorder.recorder]

}

#Module      : AWS CONFIG RUE
#Description : Provides an AWS Config Rule.
resource "aws_config_config_rule" "user_no_policies" {
  count = var.enabled && var.user_no_policies ? 1 : 0

  name = "NoPoliciesAttachedToUser"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }
  scope {
    compliance_resource_types = [
      "AWS::IAM::User",
    ]
  }
  tags       = module.labels.tags
  depends_on = [aws_config_configuration_recorder.recorder]

}

#Module      : AWS CONFIG RUE
#Description : Provides an AWS Config Rule.
resource "aws_config_config_rule" "no_policies_with_full_admin_access" {
  count = var.enabled && (var.no_policies_with_full_admin_access || var.security_pillar) ? 1 : 0
  name  = "NoPoliciesWithFullAdminAccess"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  scope {
    compliance_resource_types = [
      "AWS::IAM::Policy",
    ]
  }

  tags       = module.labels.tags
  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "acm_certificate_expiration_check" {
  count = var.enabled && (var.acm_certificate_expiration_check || var.security_pillar) ? 1 : 0

  name = "AcmCertificateExpirationCheck"

  description      = "Ensures ACM Certificates in your account are marked for expiration within the specified number of days"
  input_parameters = data.template_file.aws_config_acm_certificate_expiration.rendered

  source {
    owner             = "AWS"
    source_identifier = "ACM_CERTIFICATE_EXPIRATION_CHECK"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "ec2_volume_inuse_check" {
  count = var.enabled && (var.ec2_volume_inuse_check || var.security_pillar) ? 1 : 0

  name        = "Ec2VolumeInuseCheck"
  description = "Checks whether EBS volumes are attached to EC2 instances."

  source {
    owner             = "AWS"
    source_identifier = "EC2_VOLUME_INUSE_CHECK"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "ebs_snapshot_public_restorable" {
  count       = var.enabled && (var.ebs_snapshot_public_restorable || var.security_pillar) ? 1 : 0
  name        = "EbsSnapshotPublicRestorable"
  description = "Checks whether Amazon Elastic Block Store snapshots are not publicly restorable"

  source {
    owner             = "AWS"
    source_identifier = "EBS_SNAPSHOT_PUBLIC_RESTORABLE_CHECK"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "rds_storage_encrypted" {
  count       = var.enabled && (var.rds_storage_encrypted || var.security_pillar) ? 1 : 0
  name        = "RdsStorageEncrypted"
  description = "Checks whether storage encryption is enabled for your RDS DB instances."

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "rds_instance_public_access_check" {
  count = var.enabled && (var.rds_instance_public_access_check || var.security_pillar) ? 1 : 0

  name        = "RdsInstancePublicAccessCheck"
  description = "Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. The rule is non-compliant if the publiclyAccessible field is true in the instance configuration item."
  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_PUBLIC_ACCESS_CHECK"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "rds_snapshots_public_prohibited" {
  count = var.enabled && (var.rds_snapshots_public_prohibited || var.security_pillar) ? 1 : 0

  name        = "RdsSnapshotsPublicProhibited"
  description = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public."

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOTS_PUBLIC_PROHIBITED"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "guardduty_enabled_centralized" {
  count = var.enabled && (var.guardduty_enabled_centralized || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name        = "GuarddutyEnabledCentralized"
  description = "Checks whether Amazon GuardDuty is enabled in your AWS account and region."

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  maximum_execution_frequency = var.config_max_execution_frequency

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "s3_bucket_public_write_prohibited" {
  count = var.enabled && (var.s3_bucket_public_write_prohibited || var.security_pillar) ? 1 : 0

  name        = "S3BucketPublicWriteProhibited"
  description = "Checks that your S3 buckets do not allow public write access."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_WRITE_PROHIBITED"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "eip_attached" {
  count       = var.enabled && var.eip_attached ? 1 : 0
  name        = "EipAttached"
  description = "Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs)."

  source {
    owner             = "AWS"
    source_identifier = "EIP_ATTACHED"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "ec2_encrypted_volumes" {
  count       = var.enabled && (var.ec2_encrypted_volumes || var.security_pillar) ? 1 : 0
  name        = "Ec2VolumesMustBeEncrypted"
  description = "Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume."

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "iam_root_access_key" {
  count = var.enabled && (var.iam_root_access_key || var.security_pillar) ? 1 : 0

  name        = "IamRootAccessKey"
  description = "Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist."

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROOT_ACCESS_KEY_CHECK"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "vpc_default_security_group_closed" {
  count = var.enabled && (var.vpc_default_security_group_closed || var.security_pillar) ? 1 : 0

  name        = "VPCDefaultSecurityGroupClosed"
  description = "Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic."

  source {
    owner             = "AWS"
    source_identifier = "VPC_DEFAULT_SECURITY_GROUP_CLOSED"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_ssl_requests_only" {
  count = var.enabled && (var.s3_bucket_ssl_requests_only || var.security_pillar) ? 1 : 0

  name        = "S3BucketSSLRequestsOnly"
  description = "Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL)."

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  tags = module.labels.tags

  depends_on = [aws_config_configuration_recorder.recorder]

}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  count = var.enabled && var.config_cloudtrail_enabled ? 1 : 0

  name        = "CloudtrailEnabled"
  description = "Ensuring that the cloudtrail is enabled"

  source {

    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"

  }
  depends_on = [aws_config_configuration_recorder.recorder]
  tags       = module.labels.tags
}

resource "aws_config_config_rule" "multi_region_cloudtrail_enabled" {
  count = var.enabled && (var.multi_region_cloudtrail_enabled || var.security_pillar) ? 1 : 0

  name        = "MultiRegionCloudTrail"
  description = "Ensuring that the multi-region-cloud-trail is enabled"

  source {

    owner             = "AWS"
    source_identifier = "MULTI_REGION_CLOUD_TRAIL_ENABLED"

  }

  depends_on = [aws_config_configuration_recorder.recorder]
  tags       = module.labels.tags
}


resource "aws_config_config_rule" "instances_in_vpc" {
  count = var.enabled && (var.instances_in_vpc || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name        = "InstancesInVpc"
  description = "Ensuring that all the instances in VPC"

  source {

    owner             = "AWS"
    source_identifier = "INSTANCES_IN_VPC"

  }

  depends_on = [aws_config_configuration_recorder.recorder]
  tags       = module.labels.tags
}


resource "aws_config_config_rule" "cloudwatch_log_group_encrypted" {
  count = var.enabled && (var.cloudwatch_log_group_encrypted || var.security_pillar) ? 1 : 0

  name        = "CloudwatchLogGroupEncrypted"
  description = "Ensuring that log group is encrypted"

  source {

    owner             = "AWS"
    source_identifier = "CLOUDWATCH_LOG_GROUP_ENCRYPTED"

  }

  depends_on = [aws_config_configuration_recorder.recorder]
  tags       = module.labels.tags
}


# IAM password policy for config

data "template_file" "aws_config_iam_password_policy" {

  template = file("${path.module}/policies/password.tpl")

  vars = {

    password_require_uppercase = var.password_require_uppercase
    password_require_lowercase = var.password_require_lowercase
    password_require_symbols   = var.password_require_symbols
    password_require_numbers   = var.password_require_numbers
    password_min_length        = var.password_min_length
    password_reuse_prevention  = var.password_reuse_prevention
    password_max_age           = var.password_max_age
  }

}
resource "aws_config_config_rule" "iam_password_policy" {
  count = var.enabled && (var.iam_password_policy || var.security_pillar) ? 1 : 0

  name = "Iam_PasswordPolicy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = data.template_file.aws_config_iam_password_policy.rendered

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "Access_keys_rotated" {
  count = var.enabled && (var.Access_keys_rotated || var.security_pillar) ? 1 : 0

  name = "Acess_keys_rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }
  input_parameters = var.Access_keys_rotated_value

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "Account_part_of_organization" {
  count = var.enabled && (var.Account_part_of_organization || var.security_pillar) ? 1 : 0

  name = "Account_part_of_organization"

  source {
    owner             = "AWS"
    source_identifier = "ACCOUNT_PART_OF_ORGANIZATIONS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "alb_http_drop_invalid_header_enabled" {
  count = var.enabled && (var.alb_http_drop_invalid_header_enabled || var.security_pillar) ? 1 : 0

  name = "alb_http_drop_invalid_header_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_DROP_INVALID_HEADER_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "alb_http_to_https_redirection_check" {
  count = var.enabled && (var.alb_http_to_https_redirection_check || var.security_pillar) ? 1 : 0

  name = "alb_http_to_https_redirection_check"

  source {
    owner             = "AWS"
    source_identifier = "ALB_HTTP_TO_HTTPS_REDIRECTION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "alb_waf_enabled" {
  count = var.enabled && (var.alb_waf_enabled || var.security_pillar) ? 1 : 0

  name = "alb_waf_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ALB_WAF_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "api_gw_associated_with_waf" {
  count = var.enabled && (var.api_gw_associated_with_waf || var.security_pillar) ? 1 : 0

  name = "api_gw_associated_with_waf"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_ASSOCIATED_WITH_WAF"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "api_gw_cache_enabled_and_encrypted" {
  count = var.enabled && var.api_gw_cache_enabled_and_encrypted ? 1 : 0

  name = "api_gw_cache_enabled_and_encrypted"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_CACHE_ENABLED_AND_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "api_gw_endpoint_type_check" {
  count = var.enabled && var.api_gw_endpoint_type_check ? 1 : 0

  name = "api_gw_endpoint_type_check"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_ENDPOINT_TYPE_CHECK"
  }
  input_parameters = var.api_gw_endpoint_type_check_value

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "api_gw_execution_logging_enable" {
  count = var.enabled && (var.api_gw_execution_logging_enable || var.security_pillar) ? 1 : 0

  name = "api_gw_execution_logging_enable"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_EXECUTION_LOGGING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "api_gw_ssl_enabled" {
  count = var.enabled && (var.api_gw_ssl_enabled || var.security_pillar) ? 1 : 0

  name = "api_gw_ssl_enabled"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_SSL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "api_gw_xray_enabled" {
  count = var.enabled && var.api_gw_xray_enabled ? 1 : 0

  name = "api_gw_xray_enabled"

  source {
    owner             = "AWS"
    source_identifier = "API_GW_XRAY_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "approved_aims_by_id" {
  count = var.enabled && var.approved_aims_by_id ? 1 : 0

  name = "api_gw_xray_enabled"

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_ID"
  }
  input_parameters = var.approved_aims_by_id_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "approved_aims_by_tag" {
  count = var.enabled && var.approved_aims_by_tag ? 1 : 0

  name = "approved_aims_by_tag"

  source {
    owner             = "AWS"
    source_identifier = "APPROVED_AMIS_BY_TAG"
  }
  input_parameters = var.approved_aims_by_tag_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "aurora_mysql_backtracking_enabled" {
  count = var.enabled && var.aurora_mysql_backtracking_enabled ? 1 : 0

  name = "aurora_mysql_backtracking_enabled"

  source {
    owner             = "AWS"
    source_identifier = "AURORA_MYSQL_BACKTRACKING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "aurora_resources_protected_by_backup_plan" {
  count = var.enabled && var.aurora_resources_protected_by_backup_plan ? 1 : 0

  name = "aurora_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "AURORA_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "autoscaling_group_elb_healthcheck_required" {
  count = var.enabled && (var.autoscaling_group_elb_healthcheck_required || var.reliability_pillar) ? 1 : 0

  name = "autoscaling_group_elb_healthcheck_required"

  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_GROUP_ELB_HEALTHCHECK_REQUIRED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "autoscaling_launch_config_public_ip_disabled" {
  count = var.enabled && (var.autoscaling_launch_config_public_ip_disabled || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "autoscaling_launch_config_public_ip_disabled"

  source {
    owner             = "AWS"
    source_identifier = "AUTOSCALING_LAUNCH_CONFIG_PUBLIC_IP_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "backup_plan_min_frequency_and_min_retention_check" {
  count = var.enabled && var.backup_plan_min_frequency_and_min_retention_check ? 1 : 0

  name = "backup_plan_min_frequency_and_min_retention_check"

  source {
    owner             = "AWS"
    source_identifier = "BACKUP_PLAN_MIN_FREQUENCY_AND_MIN_RETENTION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "backup_recovery_point_encrypted" {
  count = var.enabled && var.backup_recovery_point_encrypted ? 1 : 0

  name = "backup_recovery_point_encrypted"

  source {
    owner             = "AWS"
    source_identifier = "BACKUP_RECOVERY_POINT_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "backup_recovery_point_manual_deletion_disabled" {
  count = var.enabled && var.backup_recovery_point_manual_deletion_disabled ? 1 : 0

  name = "backup_recovery_point_manual_deletion_disabled"

  source {
    owner             = "AWS"
    source_identifier = "BACKUP_RECOVERY_POINT_MANUAL_DELETION_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "backup_recovery_point_minimum_retention_check" {
  count = var.enabled && var.backup_recovery_point_minimum_retention_check ? 1 : 0

  name = "backup_recovery_point_minimum_retention_check"

  source {
    owner             = "AWS"
    source_identifier = "BACKUP_RECOVERY_POINT_MINIMUM_RETENTION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "cloudtrail_s3_dataevents_enabled" {
  count = var.enabled && (var.cloudtrail_s3_dataevents_enabled || var.security_pillar) ? 1 : 0

  name = "cloudtrail_s3_dataevents_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_S3_DATAEVENTS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudtrail_security_trail_enabled" {
  count = var.enabled && (var.cloudtrail_security_trail_enabled || var.security_pillar) ? 1 : 0

  name = "cloudtrail_s3_dataevents_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDTRAIL_SECURITY_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloud_trail_cloud_watch_logs_enabled" {
  count = var.enabled && (var.cloud_trail_cloud_watch_logs_enabled || var.security_pillar) ? 1 : 0

  name = "cloud_trail_cloud_watch_logs_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_CLOUD_WATCH_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloud_trail_enabled" {
  count = var.enabled && var.cloud_trail_enabled ? 1 : 0

  name = "cloud_trail_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloud_trail_encryption_enabled" {
  count = var.enabled && (var.cloud_trail_encryption_enabled || var.security_pillar) ? 1 : 0

  name = "cloud_trail_encryption_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "cloud_trail_log_file_validation_enabled" {
  count = var.enabled && (var.cloud_trail_log_file_validation_enabled || var.security_pillar) ? 1 : 0

  name = "cloud_trail_log_file_validation_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "db_instance_backup_enabled" {
  count = var.enabled && (var.db_instance_backup_enabled || var.reliability_pillar) ? 1 : 0

  name = "db_instance_backup_enabled"

  source {
    owner             = "AWS"
    source_identifier = "DB_INSTANCE_BACKUP_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "desired_instance_tenancy" {
  count = var.enabled && var.desired_instance_tenancy ? 1 : 0

  name = "desired_instance_tenancy"

  source {
    owner             = "AWS"
    source_identifier = "DESIRED_INSTANCE_TENANCY"
  }
  input_parameters = var.desired_instance_tenancy_value

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "desired_instance_type" {
  count = var.enabled && var.desired_instance_type ? 1 : 0

  name = "desired_instance_type"

  source {
    owner             = "AWS"
    source_identifier = "DESIRED_INSTANCE_TYPE"
  }
  input_parameters = var.desired_instance_type_value

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ebs_optimized_instance" {
  count = var.enabled && (var.ebs_optimized_instance || var.reliability_pillar) ? 1 : 0

  name = "ebs_optimized_instance"

  source {
    owner             = "AWS"
    source_identifier = "EBS_OPTIMIZED_INSTANCE"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_ebs_encryption_by_default" {
  count = var.enabled && (var.ec2_ebs_encryption_by_default || var.security_pillar) ? 1 : 0

  name = "ec2_ebs_encryption_by_default"

  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_instance_detailed_monitoring_enabled" {
  count = var.enabled && (var.ec2_instance_detailed_monitoring_enabled || var.reliability_pillar) ? 1 : 0

  name = "ec2_instance_detailed_monitoring_enabled"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_DETAILED_MONITORING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_instance_managed_by_ssm" {
  count = var.enabled && (var.ec2_instance_managed_by_ssm || var.security_pillar) ? 1 : 0

  name = "ec2_instance_managed_by_ssm"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MANAGED_BY_SSM"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_instance_profile_attached" {
  count = var.enabled && (var.ec2_instance_profile_attached || var.security_pillar) ? 1 : 0

  name = "ec2_instance_profile_attached"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_PROFILE_ATTACHED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_stopped_instance" {
  count = var.enabled && (var.ec2_stopped_instance || var.security_pillar) ? 1 : 0

  name = "ec2_stopped_instance"

  source {
    owner             = "AWS"
    source_identifier = "EC2_STOPPED_INSTANCE"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "efs_encrypted_check" {
  count = var.enabled && (var.efs_encrypted_check || var.security_pillar) ? 1 : 0

  name = "efs_encrypted_check"

  source {
    owner             = "AWS"
    source_identifier = "EFS_ENCRYPTED_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "eks_endpoint_no_public_access" {
  count = var.enabled && var.eks_endpoint_no_public_access ? 1 : 0

  name = "eks_endpoint_no_public_access"

  source {
    owner             = "AWS"
    source_identifier = "EKS_ENDPOINT_NO_PUBLIC_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "eks_secrets_encrypted" {
  count = var.enabled && var.eks_secrets_encrypted ? 1 : 0

  name = "eks_secrets_encrypted"

  source {
    owner             = "AWS"
    source_identifier = "EKS_SECRETS_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elbv2_acm_certificate_required" {
  count = var.enabled && (var.elbv2_acm_certificate_required || var.security_pillar) ? 1 : 0

  name = "elbv2_acm_certificate_required"

  source {
    owner             = "AWS"
    source_identifier = "ELBV2_ACM_CERTIFICATE_REQUIRED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_acm_certificate_required" {
  count = var.enabled && (var.elb_acm_certificate_required || var.security_pillar) ? 1 : 0

  name = "elb_acm_certificate_required"

  source {
    owner             = "AWS"
    source_identifier = "ELB_ACM_CERTIFICATE_REQUIRED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_custom_security_policy_ssl_check" {
  count = var.enabled && var.elb_custom_security_policy_ssl_check ? 1 : 0

  name = "elb_custom_security_policy_ssl_check"

  source {
    owner             = "AWS"
    source_identifier = "ELB_CUSTOM_SECURITY_POLICY_SSL_CHECK"
  }
  input_parameters = var.elb_custom_security_policy_ssl_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_deletion_protection_enabled" {
  count = var.enabled && (var.elb_deletion_protection_enabled || var.reliability_pillar) ? 1 : 0

  name = "elb_deletion_protection_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ELB_DELETION_PROTECTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_logging_enabled" {
  count = var.enabled && (var.elb_logging_enabled || var.security_pillar) ? 1 : 0

  name = "elb_logging_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ELB_LOGGING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_tls_https_listeners_only" {
  count = var.enabled && (var.elb_tls_https_listeners_only || var.security_pillar) ? 1 : 0

  name = "elb_tls_https_listeners_only"

  source {
    owner             = "AWS"
    source_identifier = "ELB_TLS_HTTPS_LISTENERS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  count = var.enabled && var.encrypted_volumes ? 1 : 0

  name = "encrypted_volumes"

  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "guardduty_non_archived_findings" {
  count = var.enabled && var.guardduty_non_archived_findings ? 1 : 0

  name = "guardduty_non_archived_findings"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_NON_ARCHIVED_FINDINGS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_no_inline_policy_check" {
  count = var.enabled && (var.iam_no_inline_policy_check || var.security_pillar) ? 1 : 0

  name = "iam_no_inline_policy_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_NO_INLINE_POLICY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_policy_blacklisted_check" {
  count = var.enabled && var.iam_policy_blacklisted_check ? 1 : 0

  name = "iam_policy_blacklisted_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_BLACKLISTED_CHECK"
  }
  input_parameters = var.iam_policy_blacklisted_check_value

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_policy_in_use" {
  count = var.enabled && var.iam_policy_in_use ? 1 : 0

  name = "iam_policy_in_use"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_IN_USE"
  }
  input_parameters = var.iam_policy_in_use_arn

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_user_mfa_enabled" {
  count = var.enabled && (var.iam_user_mfa_enabled || var.security_pillar) ? 1 : 0

  name = "iam_user_mfa_enabled"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "incoming_ssh_disabled" {
  count = var.enabled && (var.incoming_ssh_disabled || var.security_pillar) ? 1 : 0

  name = "incoming_ssh_disabled"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "internet_gateway_authorized_vpc_only" {
  count = var.enabled && var.internet_gateway_authorized_vpc_only ? 1 : 0

  name = "internet_gateway_authorized_vpc_only"

  source {
    owner             = "AWS"
    source_identifier = "INTERNET_GATEWAY_AUTHORIZED_VPC_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "lambda_concurrency_check" {
  count = var.enabled && (var.lambda_concurrency_check || var.reliability_pillar) ? 1 : 0

  name = "lambda_concurrency_check"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_CONCURRENCY_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "lambda_dlq_check" {
  count = var.enabled && (var.lambda_dlq_check || var.reliability_pillar) ? 1 : 0

  name = "lambda_dlq_check"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_DLQ_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "lambda_function_public_access_prohibited" {
  count = var.enabled && (var.lambda_function_public_access_prohibited || var.security_pillar) ? 1 : 0

  name = "lambda_function_public_access_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "lambda_function_settings_check" {
  count = var.enabled && var.lambda_function_settings_check ? 1 : 0

  name = "lambda_function_settings_check"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_FUNCTION_SETTINGS_CHECK"
  }
  input_parameters = var.lambda_function_settings_check_value

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "lambda_inside_vpc" {
  count = var.enabled && (var.lambda_inside_vpc || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "lambda_inside_vpc"

  source {
    owner             = "AWS"
    source_identifier = "LAMBDA_INSIDE_VPC"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "mfa_enabled_for_iam_console_access" {
  count = var.enabled && (var.mfa_enabled_for_iam_console_access || var.security_pillar) ? 1 : 0

  name = "mfa_enabled_for_iam_console_access"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "no_unrestricted_route_to_igw" {
  count = var.enabled && (var.no_unrestricted_route_to_igw || var.security_pillar) ? 1 : 0

  name = "no_unrestricted_route_to_igw"

  source {
    owner             = "AWS"
    source_identifier = "NO_UNRESTRICTED_ROUTE_TO_IGW"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_automatic_minor_version_upgrade_enabled" {
  count = var.enabled && (var.rds_automatic_minor_version_upgrade_enabled || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "rds_automatic_minor_version_upgrade_enabled"

  source {
    owner             = "AWS"
    source_identifier = "NO_UNRESTRICTED_ROUTE_TO_IGW"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_cluster_deletion_protection_enabled" {
  count = var.enabled && var.rds_cluster_deletion_protection_enabled ? 1 : 0

  name = "rds_cluster_deletion_protection_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_CLUSTER_DELETION_PROTECTION_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_cluster_iam_authentication_enabled" {
  count = var.enabled && var.rds_cluster_iam_authentication_enabled ? 1 : 0

  name = "rds_cluster_iam_authentication_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_CLUSTER_IAM_AUTHENTICATION_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_cluster_multi_az_enabled" {
  count = var.enabled && var.rds_cluster_multi_az_enabled ? 1 : 0

  name = "rds_cluster_multi_az_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_CLUSTER_MULTI_AZ_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_enhanced_monitoring_enabled" {
  count = var.enabled && (var.rds_enhanced_monitoring_enabled || var.reliability_pillar) ? 1 : 0

  name = "rds_enhanced_monitoring_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_ENHANCED_MONITORING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_instance_deletion_protection_enabled" {
  count = var.enabled && (var.rds_instance_deletion_protection_enabled || var.reliability_pillar) ? 1 : 0

  name = "rds_instance_deletion_protection_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_DELETION_PROTECTION_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_instance_iam_authentication_enabled" {
  count = var.enabled && var.rds_instance_iam_authentication_enabled ? 1 : 0

  name = "rds_instance_iam_authentication_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_INSTANCE_IAM_AUTHENTICATION_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "rds_logging_enabled" {
  count = var.enabled && (var.rds_logging_enabled || var.security_pillar) ? 1 : 0

  name = "rds_logging_enabled"

  source {
    owner             = "AWS"
    source_identifier = "RDS_LOGGING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_multi_az_support" {
  count = var.enabled && (var.rds_multi_az_support || var.reliability_pillar) ? 1 : 0

  name = "rds_multi_az_support"

  source {
    owner             = "AWS"
    source_identifier = "RDS_MULTI_AZ_SUPPORT"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_snapshot_encrypted" {
  count = var.enabled && (var.rds_snapshot_encrypted || var.security_pillar) ? 1 : 0

  name = "rds_snapshot_encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_SNAPSHOT_ENCRYPTED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "root_account_mfa_enabled" {
  count = var.enabled && (var.root_account_mfa_enabled || var.security_pillar) ? 1 : 0

  name = "root_account_mfa_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_logging_enabled" {
  count = var.enabled && (var.s3_bucket_logging_enabled || var.security_pillar) ? 1 : 0

  name = "s3_bucket_logging_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LOGGING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_server_side_encryption_enabled" {
  count = var.enabled && (var.s3_bucket_server_side_encryption_enabled || var.security_pillar) ? 1 : 0

  name = "s3_bucket_server_side_encryption_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_versioning_enabled" {
  count = var.enabled && (var.s3_bucket_versioning_enabled || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "s3_bucket_versioning_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_VERSIONING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_default_encryption_kms" {
  count = var.enabled && (var.s3_default_encryption_kms || var.security_pillar) ? 1 : 0

  name = "s3_default_encryption_kms"

  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "secretsmanager_secret_unused" {
  count = var.enabled && (var.secretsmanager_secret_unused || var.security_pillar) ? 1 : 0

  name = "secretsmanager_secret_unused"

  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_SECRET_UNUSED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "sns_encrypted_kms" {
  count = var.enabled && (var.sns_encrypted_kms || var.security_pillar) ? 1 : 0

  name = "sns_encrypted_kms"

  source {
    owner             = "AWS"
    source_identifier = "SNS_ENCRYPTED_KMS"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "vpc_flow_logs_enabled" {
  count = var.enabled && (var.vpc_flow_logs_enabled || var.security_pillar) ? 1 : 0

  name = "vpc_flow_logs_enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "wafv2_logging_enabled" {
  count = var.enabled && (var.wafv2_logging_enabled || var.security_pillar) ? 1 : 0

  name = "wafv2_logging_enabled"

  source {
    owner             = "AWS"
    source_identifier = "WAFV2_LOGGING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "beanstalk_enhanced_health_reporting_enabled" {
  count = var.enabled && (var.beanstalk_enhanced_health_reporting_enabled || var.reliability_pillar) ? 1 : 0

  name = "beanstalk_enhanced_health_reporting_enabled"

  source {
    owner             = "AWS"
    source_identifier = "BEANSTALK_ENHANCED_HEALTH_REPORTING_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_accesslogs_enabled" {
  count = var.enabled && var.cloudfront_accesslogs_enabled ? 1 : 0

  name = "cloudfront_accesslogs_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_ACCESSLOGS_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_associated_with_waf" {
  count = var.enabled && var.cloudfront_associated_with_waf ? 1 : 0

  name = "cloudfront_associated_with_waf"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_ASSOCIATED_WITH_WAF"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_custom_ssl_certificate" {
  count = var.enabled && var.cloudfront_custom_ssl_certificate ? 1 : 0

  name = "cloudfront_custom_ssl_certificate"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_CUSTOM_SSL_CERTIFICATE"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_default_root_object_configured" {
  count = var.enabled && var.cloudfront_default_root_object_configured ? 1 : 0

  name = "cloudfront_default_root_object_configured"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_DEFAULT_ROOT_OBJECT_CONFIGURED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_origin_access_identity_enabled" {
  count = var.enabled && var.cloudfront_origin_access_identity_enabled ? 1 : 0

  name = "cloudfront_origin_access_identity_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_ORIGIN_ACCESS_IDENTITY_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_origin_failover_enabled" {
  count = var.enabled && var.cloudfront_origin_failover_enabled ? 1 : 0

  name = "cloudfront_origin_failover_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_ORIGIN_FAILOVER_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_sni_enabled" {
  count = var.enabled && var.cloudfront_sni_enabled ? 1 : 0

  name = "cloudfront_sni_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_SNI_ENABLED"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudfront_viewer_policy_https" {
  count = var.enabled && var.cloudfront_viewer_policy_https ? 1 : 0

  name = "cloudfront_viewer_policy_https"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFRONT_VIEWER_POLICY_HTTPS"
  }


  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudwatch_alarm_action_check" {
  count = var.enabled && (var.cloudwatch_alarm_action_check || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "cloudwatch_alarm_action_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_ACTION_CHECK"
  }

  input_parameters = var.cloudwatch_alarm_action_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudwatch_alarm_resource_check" {
  count = var.enabled && var.cloudwatch_alarm_resource_check ? 1 : 0

  name = "cloudwatch_alarm_resource_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_RESOURCE_CHECK"
  }

  input_parameters = var.cloudwatch_alarm_resource_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudwatch_alarm_settings_check" {
  count = var.enabled && var.cloudwatch_alarm_settings_check ? 1 : 0

  name = "cloudwatch_alarm_settings_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDWATCH_ALARM_SETTINGS_CHECK"
  }

  input_parameters = var.cloudwatch_alarm_settings_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cmk_backing_key_rotation_enabled" {
  count = var.enabled && var.cmk_backing_key_rotation_enabled ? 1 : 0

  name = "cmk_backing_key_rotation_enabled"

  source {
    owner             = "AWS"
    source_identifier = "CMK_BACKING_KEY_ROTATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "codebuild_project_envvar_awscred_check" {
  count = var.enabled && (var.codebuild_project_envvar_awscred_check || var.security_pillar) ? 1 : 0

  name = "codebuild_project_envvar_awscred_check"

  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_ENVVAR_AWSCRED_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "codebuild_project_source_repo_url_check" {
  count = var.enabled && var.codebuild_project_source_repo_url_check ? 1 : 0

  name = "codebuild_project_source_repo_url_check"

  source {
    owner             = "AWS"
    source_identifier = "CODEBUILD_PROJECT_SOURCE_REPO_URL_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "codepipeline_deployment_count_check" {
  count = var.enabled && var.codepipeline_deployment_count_check ? 1 : 0

  name = "codepipeline_deployment_count_check"

  source {
    owner             = "AWS"
    source_identifier = "CODEPIPELINE_DEPLOYMENT_COUNT_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "codepipeline_region_fanout_check" {
  count = var.enabled && var.codepipeline_region_fanout_check ? 1 : 0

  name = "codepipeline_region_fanout_check"

  source {
    owner             = "AWS"
    source_identifier = "CODEPIPELINE_REGION_FANOUT_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cw_loggroup_retention_period_check" {
  count = var.enabled && (var.cw_loggroup_retention_period_check || var.security_pillar) ? 1 : 0

  name = "cw_loggroup_retention_period_check"

  source {
    owner             = "AWS"
    source_identifier = "CW_LOGGROUP_RETENTION_PERIOD_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dax_encryption_enabled" {
  count = var.enabled && var.dax_encryption_enabled ? 1 : 0

  name = "dax_encryption_enabled"

  source {
    owner             = "AWS"
    source_identifier = "DAX_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dms_replication_not_public" {
  count = var.enabled && (var.dms_replication_not_public || var.security_pillar) ? 1 : 0

  name = "dms_replication_not_public"

  source {
    owner             = "AWS"
    source_identifier = "DMS_REPLICATION_NOT_PUBLIC"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_autoscaling_enabled" {
  count = var.enabled && (var.dynamodb_autoscaling_enabled || var.reliability_pillar) ? 1 : 0

  name = "dynamodb_autoscaling_enabled"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_AUTOSCALING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_in_backup_plan" {
  count = var.enabled && (var.dynamodb_in_backup_plan || var.reliability_pillar) ? 1 : 0

  name = "dynamodb_in_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_IN_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_pitr_enabled" {
  count = var.enabled && (var.dynamodb_pitr_enabled || var.reliability_pillar) ? 1 : 0

  name = "dynamodb_pitr_enabled"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_PITR_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_resources_protected_by_backup_plan" {
  count = var.enabled && var.dynamodb_resources_protected_by_backup_plan ? 1 : 0

  name = "dynamodb_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_table_encrypted_kms" {
  count = var.enabled && (var.dynamodb_table_encrypted_kms || var.security_pillar) ? 1 : 0

  name = "dynamodb_table_encrypted_kms"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTED_KMS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_table_encryption_enabled" {
  count = var.enabled && var.dynamodb_table_encryption_enabled ? 1 : 0

  name = "dynamodb_table_encryption_enabled"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_TABLE_ENCRYPTION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "dynamodb_throughput_limit_check" {
  count = var.enabled && (var.dynamodb_throughput_limit_check || var.reliability_pillar) ? 1 : 0

  name = "dynamodb_throughput_limit_check"

  source {
    owner             = "AWS"
    source_identifier = "DYNAMODB_THROUGHPUT_LIMIT_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ebs_in_backup_plan" {
  count = var.enabled && (var.ebs_in_backup_plan || var.reliability_pillar) ? 1 : 0

  name = "ebs_in_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "EBS_IN_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ebs_resources_protected_by_backup_plan" {
  count = var.enabled && var.ebs_resources_protected_by_backup_plan ? 1 : 0

  name = "ebs_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "EBS_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_imdsv2_check" {
  count = var.enabled && (var.ec2_imdsv2_check || var.security_pillar) ? 1 : 0

  name = "ec2_imdsv2_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_IMDSV2_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_instance_multiple_eni_check" {
  count = var.enabled && (var.ec2_instance_multiple_eni_check || var.security_pillar) ? 1 : 0

  name = "ec2_instance_multiple_eni_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_MULTIPLE_ENI_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_instance_no_public_ip" {
  count = var.enabled && (var.ec2_instance_no_public_ip || var.security_pillar) ? 1 : 0

  name = "ec2_instance_no_public_ip"

  source {
    owner             = "AWS"
    source_identifier = "EC2_INSTANCE_NO_PUBLIC_IP"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_applications_blacklisted" {
  count = var.enabled && var.ec2_managedinstance_applications_blacklisted ? 1 : 0

  name = "ec2_managedinstance_applications_blacklisted"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_APPLICATIONS_BLACKLISTED"
  }
  input_parameters = var.ec2_managedinstance_applications_blacklisted_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_applications_required" {
  count = var.enabled && var.ec2_managedinstance_applications_required ? 1 : 0

  name = "ec2_managedinstance_applications_required"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_APPLICATIONS_REQUIRED"
  }
  input_parameters = var.ec2_managedinstance_applications_required_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_association_compliance_status_check" {
  count = var.enabled && (var.ec2_managedinstance_association_compliance_status_check || var.security_pillar) ? 1 : 0

  name = "ec2_managedinstance_association_compliance_status_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_ASSOCIATION_COMPLIANCE_STATUS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_inventory_blacklisted" {
  count = var.enabled && var.ec2_managedinstance_inventory_blacklisted ? 1 : 0

  name = "ec2_managedinstance_inventory_blacklisted"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_INVENTORY_BLACKLISTED"
  }
  input_parameters = var.ec2_managedinstance_inventory_blacklisted_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_patch_compliance_status_check" {
  count = var.enabled && (var.ec2_managedinstance_patch_compliance_status_check || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "ec2_managedinstance_patch_compliance_status_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PATCH_COMPLIANCE_STATUS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_managedinstance_platform_check" {
  count = var.enabled && var.ec2_managedinstance_platform_check ? 1 : 0

  name = "ec2_managedinstance_platform_check"

  source {
    owner             = "AWS"
    source_identifier = "EC2_MANAGEDINSTANCE_PLATFORM_CHECK"
  }
  input_parameters = var.ec2_managedinstance_platform_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_resources_protected_by_backup_plan" {
  count = var.enabled && var.ec2_resources_protected_by_backup_plan ? 1 : 0

  name = "ec2_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "EC2_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ec2_security_group_attached_to_eni" {
  count = var.enabled && (var.ec2_security_group_attached_to_eni || var.security_pillar) ? 1 : 0

  name = "ec2_security_group_attached_to_eni"

  source {
    owner             = "AWS"
    source_identifier = "EC2_SECURITY_GROUP_ATTACHED_TO_ENI"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ecs_task_definition_user_for_host_mode_check" {
  count = var.enabled && (var.ecs_task_definition_user_for_host_mode_check || var.security_pillar) ? 1 : 0

  name = "ecs_task_definition_user_for_host_mode_check"

  source {
    owner             = "AWS"
    source_identifier = "ECS_TASK_DEFINITION_USER_FOR_HOST_MODE_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "efs_in_backup_plan" {
  count = var.enabled && (var.efs_in_backup_plan || var.reliability_pillar) ? 1 : 0

  name = "efs_in_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "EFS_IN_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "efs_resources_protected_by_backup_plan" {
  count = var.enabled && var.efs_resources_protected_by_backup_plan ? 1 : 0

  name = "efs_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "EFS_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elasticache_redis_cluster_automatic_backup_check" {
  count = var.enabled && (var.elasticache_redis_cluster_automatic_backup_check || var.reliability_pillar) ? 1 : 0

  name = "elasticache_redis_cluster_automatic_backup_check"

  source {
    owner             = "AWS"
    source_identifier = "ELASTICACHE_REDIS_CLUSTER_AUTOMATIC_BACKUP_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elasticsearch_encrypted_at_rest" {
  count = var.enabled && (var.elasticsearch_encrypted_at_rest || var.security_pillar) ? 1 : 0

  name = "elasticsearch_encrypted_at_rest"

  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_ENCRYPTED_AT_REST"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elasticsearch_logs_to_cloudwatch" {
  count = var.enabled && (var.elasticsearch_logs_to_cloudwatch || var.security_pillar) ? 1 : 0

  name = "elasticsearch_logs_to_cloudwatch"

  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_LOGS_TO_CLOUDWATCH"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elasticsearch_node_to_node_encryption_check" {
  count = var.enabled && (var.elasticsearch_node_to_node_encryption_check || var.security_pillar) ? 1 : 0

  name = "elasticsearch_node_to_node_encryption_check"

  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_NODE_TO_NODE_ENCRYPTION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elastic_beanstalk_managed_updates_enabled" {
  count = var.enabled && (var.elastic_beanstalk_managed_updates_enabled || var.security_pillar) ? 1 : 0

  name = "elastic_beanstalk_managed_updates_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ELASTIC_BEANSTALK_MANAGED_UPDATES_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_cross_zone_load_balancing_enabled" {
  count = var.enabled && (var.elb_cross_zone_load_balancing_enabled || var.reliability_pillar) ? 1 : 0

  name = "elb_cross_zone_load_balancing_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ELB_CROSS_ZONE_LOAD_BALANCING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elb_predefined_security_policy_ssl_check" {
  count = var.enabled && var.elb_predefined_security_policy_ssl_check ? 1 : 0

  name = "elb_predefined_security_policy_ssl_check"

  source {
    owner             = "AWS"
    source_identifier = "ELB_PREDEFINED_SECURITY_POLICY_SSL_CHECK"
  }
  input_parameters = var.elb_predefined_security_policy_ssl_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "emr_kerberos_enabled" {
  count = var.enabled && (var.emr_kerberos_enabled || var.security_pillar) ? 1 : 0

  name = "emr_kerberos_enabled"

  source {
    owner             = "AWS"
    source_identifier = "EMR_KERBEROS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "emr_master_no_public_ip" {
  count = var.enabled && (var.emr_master_no_public_ip || var.security_pillar) ? 1 : 0

  name = "emr_master_no_public_ip"

  source {
    owner             = "AWS"
    source_identifier = "EMR_MASTER_NO_PUBLIC_IP"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "fms_shield_resource_policy_check" {
  count = var.enabled && var.fms_shield_resource_policy_check ? 1 : 0

  name = "fms_shield_resource_policy_check"

  source {
    owner             = "AWS"
    source_identifier = "FMS_SHIELD_RESOURCE_POLICY_CHECK"
  }
  input_parameters = var.fms_shield_resource_policy_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "fms_webacl_resource_policy_check" {
  count = var.enabled && var.fms_webacl_resource_policy_check ? 1 : 0

  name = "fms_webacl_resource_policy_check"

  source {
    owner             = "AWS"
    source_identifier = "FMS_WEBACL_RESOURCE_POLICY_CHECK"
  }
  input_parameters = var.fms_webacl_resource_policy_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "fms_webacl_rulegroup_association_check" {
  count = var.enabled && var.fms_webacl_rulegroup_association_check ? 1 : 0

  name = "fms_webacl_rulegroup_association_check"

  source {
    owner             = "AWS"
    source_identifier = "FMS_WEBACL_RULEGROUP_ASSOCIATION_CHECK"
  }
  input_parameters = var.fms_webacl_rulegroup_association_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "fsx_resources_protected_by_backup_plan" {
  count = var.enabled && var.fsx_resources_protected_by_backup_plan ? 1 : 0

  name = "fsx_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "FSX_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_customer_policy_blocked_kms_actions" {
  count = var.enabled && var.iam_customer_policy_blocked_kms_actions ? 1 : 0

  name = "iam_customer_policy_blocked_kms_actions"

  source {
    owner             = "AWS"
    source_identifier = "IAM_CUSTOMER_POLICY_BLOCKED_KMS_ACTIONS"
  }
  input_parameters = var.iam_customer_policy_blocked_kms_actions_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_group_has_users_check" {
  count = var.enabled && (var.iam_group_has_users_check || var.security_pillar) ? 1 : 0

  name = "iam_group_has_users_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_GROUP_HAS_USERS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_inline_policy_blocked_kms_actions" {
  count = var.enabled && var.iam_inline_policy_blocked_kms_actions ? 1 : 0

  name = "iam_inline_policy_blocked_kms_actions"

  source {
    owner             = "AWS"
    source_identifier = "IAM_INLINE_POLICY_BLOCKED_KMS_ACTIONS"
  }
  input_parameters = var.iam_inline_policy_blocked_kms_actions_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_policy_no_statements_with_full_access" {
  count = var.enabled && (var.iam_policy_no_statements_with_full_access || var.security_pillar) ? 1 : 0

  name = "iam_policy_no_statements_with_full_access"

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_FULL_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_role_managed_policy_check" {
  count = var.enabled && var.iam_role_managed_policy_check ? 1 : 0

  name = "iam_role_managed_policy_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_ROLE_MANAGED_POLICY_CHECK"
  }
  input_parameters = var.iam_role_managed_policy_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "iam_user_group_membership_check" {
  count = var.enabled && (var.iam_user_group_membership_check || var.security_pillar) ? 1 : 0

  name = "iam_user_group_membership_check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_GROUP_MEMBERSHIP_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "kms_cmk_not_scheduled_for_deletion" {
  count = var.enabled && (var.kms_cmk_not_scheduled_for_deletion || var.security_pillar) ? 1 : 0

  name = "kms_cmk_not_scheduled_for_deletion"

  source {
    owner             = "AWS"
    source_identifier = "KMS_CMK_NOT_SCHEDULED_FOR_DELETION"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "rds_in_backup_plan" {
  count = var.enabled && (var.rds_in_backup_plan || var.reliability_pillar) ? 1 : 0

  name = "rds_in_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "RDS_IN_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "rds_resources_protected_by_backup_plan" {
  count = var.enabled && var.rds_resources_protected_by_backup_plan ? 1 : 0

  name = "rds_resources_protected_by_backup_plan"

  source {
    owner             = "AWS"
    source_identifier = "RDS_RESOURCES_PROTECTED_BY_BACKUP_PLAN"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_backup_enabled" {
  count = var.enabled && (var.redshift_backup_enabled || var.reliability_pillar) ? 1 : 0

  name = "redshift_backup_enabled"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_BACKUP_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_cluster_configuration_check" {
  count = var.enabled && (var.redshift_cluster_configuration_check || var.security_pillar) ? 1 : 0

  name = "redshift_cluster_configuration_check"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_CONFIGURATION_CHECK"
  }
  input_parameters = var.redshift_cluster_configuration_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_cluster_kms_enabled" {
  count = var.enabled && (var.redshift_cluster_kms_enabled || var.security_pillar) ? 1 : 0

  name = "redshift_cluster_kms_enabled"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_KMS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_cluster_maintenancesettings_check" {
  count = var.enabled && (var.redshift_cluster_maintenancesettings_check || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "redshift_cluster_maintenancesettings_check"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_MAINTENANCESETTINGS_CHECK"
  }
  input_parameters = var.redshift_cluster_maintenancesettings_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_cluster_public_access_check" {
  count = var.enabled && (var.redshift_cluster_public_access_check || var.security_pillar) ? 1 : 0

  name = "redshift_cluster_public_access_check"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_CLUSTER_PUBLIC_ACCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_enhanced_vpc_routing_enabled" {
  count = var.enabled && (var.redshift_enhanced_vpc_routing_enabled || var.security_pillar) ? 1 : 0

  name = "redshift_enhanced_vpc_routing_enabled"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_ENHANCED_VPC_ROUTING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "redshift_require_tls_ssl" {
  count = var.enabled && (var.redshift_require_tls_ssl || var.security_pillar) ? 1 : 0

  name = "redshift_require_tls_ssl"

  source {
    owner             = "AWS"
    source_identifier = "REDSHIFT_REQUIRE_TLS_SSL"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "required_tags" {
  count = var.enabled && var.required_tags ? 1 : 0

  name = "required_tags"

  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"
  }
  input_parameters = var.required_tags_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "restricted-common-ports" {
  count = var.enabled && (var.restricted-common-ports || var.security_pillar) ? 1 : 0

  name = "restricted-common-ports"

  source {
    owner             = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "root_account_hardware_mfa_enabled" {
  count = var.enabled && (var.root_account_hardware_mfa_enabled || var.security_pillar) ? 1 : 0

  name = "root_account_hardware_mfa_enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_HARDWARE_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_account_level_public_access_blocks" {
  count = var.enabled && var.s3_account_level_public_access_blocks ? 1 : 0

  name = "s3_account_level_public_access_blocks"

  source {
    owner             = "AWS"
    source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_account_level_public_access_blocks_periodic" {
  count = var.enabled && (var.s3_account_level_public_access_blocks_periodic || var.security_pillar) ? 1 : 0

  name = "s3_account_level_public_access_blocks_periodic"

  source {
    owner             = "AWS"
    source_identifier = "S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS_PERIODIC"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_blacklisted_actions_prohibited" {
  count = var.enabled && var.s3_bucket_blacklisted_actions_prohibited ? 1 : 0

  name = "s3_bucket_blacklisted_actions_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_BLACKLISTED_ACTIONS_PROHIBITED"
  }
  input_parameters = var.s3_bucket_blacklisted_actions_prohibited_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_default_lock_enabled" {
  count = var.enabled && (var.s3_bucket_default_lock_enabled || var.reliability_pillar) ? 1 : 0

  name = "s3_bucket_default_lock_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_DEFAULT_LOCK_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_level_public_access_prohibited" {
  count = var.enabled && (var.s3_bucket_level_public_access_prohibited || var.security_pillar) ? 1 : 0

  name = "s3_bucket_level_public_access_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_policy_grantee_check" {
  count = var.enabled && var.s3_bucket_policy_grantee_check ? 1 : 0

  name = "s3_bucket_policy_grantee_check"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_GRANTEE_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_policy_not_more_permissive" {
  count = var.enabled && var.s3_bucket_policy_not_more_permissive ? 1 : 0

  name = "s3_bucket_policy_not_more_permissive"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_POLICY_NOT_MORE_PERMISSIVE"
  }
  input_parameters = var.s3_bucket_policy_not_more_permissive_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "s3_bucket_public_read_prohibited" {
  count = var.enabled && (var.s3_bucket_public_read_prohibited || var.security_pillar) ? 1 : 0

  name = "s3_bucket_public_read_prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "s3_bucket_replication_enabled" {
  count = var.enabled && (var.s3_bucket_replication_enabled || var.reliability_pillar) ? 1 : 0

  name = "s3_bucket_replication_enabled"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_REPLICATION_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "sagemaker_endpoint_configuration_kms_key_configured" {
  count = var.enabled && (var.sagemaker_endpoint_configuration_kms_key_configured || var.security_pillar) ? 1 : 0

  name = "sagemaker_endpoint_configuration_kms_key_configured"

  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_ENDPOINT_CONFIGURATION_KMS_KEY_CONFIGURED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "sagemaker_notebook_instance_kms_key_configured" {
  count = var.enabled && (var.sagemaker_notebook_instance_kms_key_configured || var.security_pillar) ? 1 : 0

  name = "sagemaker_notebook_instance_kms_key_configured"

  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_INSTANCE_KMS_KEY_CONFIGURED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "sagemaker_notebook_no_direct_internet_access" {
  count = var.enabled && (var.sagemaker_notebook_no_direct_internet_access || var.security_pillar) ? 1 : 0

  name = "sagemaker_notebook_no_direct_internet_access"

  source {
    owner             = "AWS"
    source_identifier = "SAGEMAKER_NOTEBOOK_NO_DIRECT_INTERNET_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "secretsmanager_rotation_enabled_check" {
  count = var.enabled && (var.secretsmanager_rotation_enabled_check || var.security_pillar) ? 1 : 0

  name = "secretsmanager_rotation_enabled_check"

  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_ROTATION_ENABLED_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "secretsmanager_scheduled_rotation_success_check" {
  count = var.enabled && (var.secretsmanager_scheduled_rotation_success_check || var.security_pillar) ? 1 : 0

  name = "secretsmanager_scheduled_rotation_success_check"

  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_SCHEDULED_ROTATION_SUCCESS_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "secretsmanager_secret_periodic_rotation" {
  count = var.enabled && (var.secretsmanager_secret_periodic_rotation || var.security_pillar) ? 1 : 0

  name = "secretsmanager_secret_periodic_rotation"

  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_SECRET_PERIODIC_ROTATION"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "secretsmanager_using_cmk" {
  count = var.enabled && (var.secretsmanager_using_cmk || var.security_pillar) ? 1 : 0

  name = "secretsmanager_using_cmk"

  source {
    owner             = "AWS"
    source_identifier = "SECRETSMANAGER_USING_CMK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "securityhub_enabled" {
  count = var.enabled && (var.securityhub_enabled || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "securityhub_enabled"

  source {
    owner             = "AWS"
    source_identifier = "SECURITYHUB_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "service_vpc_endpoint_enabled" {
  count = var.enabled && var.service_vpc_endpoint_enabled ? 1 : 0

  name = "service_vpc_endpoint_enabled"

  source {
    owner             = "AWS"
    source_identifier = "SERVICE_VPC_ENDPOINT_ENABLED"
  }
  input_parameters = var.service_vpc_endpoint_enabled_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "shield_advanced_enabled_autorenew" {
  count = var.enabled && var.shield_advanced_enabled_autorenew ? 1 : 0

  name = "shield_advanced_enabled_autorenew"

  source {
    owner             = "AWS"
    source_identifier = "SHIELD_ADVANCED_ENABLED_AUTORENEW"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "shield_drt_access" {
  count = var.enabled && var.shield_drt_access ? 1 : 0

  name = "shield_drt_access"

  source {
    owner             = "AWS"
    source_identifier = "SHIELD_DRT_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "ssm_document_not_public" {
  count = var.enabled && (var.ssm_document_not_public || var.security_pillar) ? 1 : 0

  name = "ssm_document_not_public"

  source {
    owner             = "AWS"
    source_identifier = "SSM_DOCUMENT_NOT_PUBLIC"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "subnet_auto_assign_public_ip_disabled" {
  count = var.enabled && (var.subnet_auto_assign_public_ip_disabled || var.security_pillar) ? 1 : 0

  name = "subnet_auto_assign_public_ip_disabled"

  source {
    owner             = "AWS"
    source_identifier = "SUBNET_AUTO_ASSIGN_PUBLIC_IP_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "vpc_network_acl_unused_check" {
  count = var.enabled && var.vpc_network_acl_unused_check ? 1 : 0

  name = "vpc_network_acl_unused_check"

  source {
    owner             = "AWS"
    source_identifier = "VPC_NETWORK_ACL_UNUSED_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "vpc_sg_open_only_to_authorized_ports" {
  count = var.enabled && (var.vpc_sg_open_only_to_authorized_ports || var.security_pillar) ? 1 : 0

  name = "vpc_sg_open_only_to_authorized_ports"

  source {
    owner             = "AWS"
    source_identifier = "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "vpc_vpn_2_tunnels_up" {
  count = var.enabled && (var.vpc_vpn_2_tunnels_up || var.reliability_pillar) ? 1 : 0

  name = "vpc_vpn_2_tunnels_up"

  source {
    owner             = "AWS"
    source_identifier = "VPC_VPN_2_TUNNELS_UP"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}


resource "aws_config_config_rule" "waf_classic_logging_enabled" {
  count = var.enabled && var.waf_classic_logging_enabled ? 1 : 0

  name = "waf_classic_logging_enabled"

  source {
    owner             = "AWS"
    source_identifier = "WAF_CLASSIC_LOGGING_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudformation_stack_drift_detection_check" {
  count = var.enabled && var.cloudformation_stack_drift_detection_check ? 1 : 0

  name = "cloudformation_stack_drift_detection_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFORMATION_STACK_DRIFT_DETECTION_CHECK"
  }
  input_parameters = var.cloudformation_stack_drift_detection_check_value
  depends_on       = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "cloudformation_stack_notification_check" {
  count = var.enabled && var.cloudformation_stack_notification_check ? 1 : 0

  name = "cloudformation_stack_notification_check"

  source {
    owner             = "AWS"
    source_identifier = "CLOUDFORMATION_STACK_NOTIFICATION_CHECK"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}

resource "aws_config_config_rule" "elasticsearch_in_vpc_only" {
  count = var.enabled && (var.elasticsearch_in_vpc_only || var.reliability_pillar || var.security_pillar) ? 1 : 0

  name = "elasticsearch_in_vpc_only"

  source {
    owner             = "AWS"
    source_identifier = "ELASTICSEARCH_IN_VPC_ONLY"
  }

  depends_on = [aws_config_configuration_recorder.recorder]
}