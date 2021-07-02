## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "0.15.0"

  name        = var.name
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
  source  = "clouddrove/lambda/aws"
  version = "0.15.0"

  name        = "config-lambda"
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
  source  = "clouddrove/sns/aws"
  version = "0.15.0"

  name         = "alarm-sns"
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
  source  = "clouddrove/s3/aws"
  version = "0.15.0"

  name        = var.config_s3_bucket_name
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
      format("arn:aws:s3:::%s%s/config/AWSLogs/%s/*", var.config_s3_bucket_name, var.delimiter, data.aws_caller_identity.current.account_id),
    ]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [format("arn:aws:s3:::%s%s", var.config_s3_bucket_name, var.delimiter)]
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
  count = var.enabled && var.iam_mfa ? 1 : 0

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
  count = var.enabled && var.unused_credentials ? 1 : 0

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
  count = var.enabled && var.no_policies_with_full_admin_access ? 1 : 0
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
  count = var.enabled && var.acm_certificate_expiration_check ? 1 : 0

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
  count = var.enabled && var.ec2_volume_inuse_check ? 1 : 0

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
  count       = var.enabled && var.ebs_snapshot_public_restorable ? 1 : 0
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
  count       = var.enabled && var.rds_storage_encrypted ? 1 : 0
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
  count = var.enabled && var.rds_instance_public_access_check ? 1 : 0

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
  count = var.enabled && var.rds_snapshots_public_prohibited ? 1 : 0

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
  count = var.enabled && var.guardduty_enabled_centralized ? 1 : 0

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
  count = var.enabled && var.s3_bucket_public_write_prohibited ? 1 : 0

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
  count       = var.enabled && var.ec2_encrypted_volumes ? 1 : 0
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
  count = var.enabled && var.iam_root_access_key ? 1 : 0

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
  count = var.enabled && var.vpc_default_security_group_closed ? 1 : 0

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
  count = var.enabled && var.s3_bucket_ssl_requests_only ? 1 : 0

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
  count = var.enabled && var.multi_region_cloudtrail_enabled ? 1 : 0

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
  count = var.enabled && var.instances_in_vpc ? 1 : 0

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
  count = var.enabled && var.cloudwatch_log_group_encrypted ? 1 : 0

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
  count = var.enabled && var.iam_password_policy ? 1 : 0

  name = "Iam_PasswordPolicy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = data.template_file.aws_config_iam_password_policy.rendered

  depends_on = [aws_config_configuration_recorder.recorder]
}
