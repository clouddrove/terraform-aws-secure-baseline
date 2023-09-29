
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Template file for the AWS Config ACM certificate
data "template_file" "aws_config_acm_certificate_expiration" {
  template = file(
    "${path.module}/policies/acm-certificate-expiration.tpl"
  )

  vars = {
    acm_days_to_expiration = var.acm_days_to_expiration
  }
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

# Getting AssumeRole policy for IAM.
data "aws_iam_policy_document" "recorder_assume_role_policy" {
  statement {
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    actions = ["sts:AssumeRole"]
  }
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