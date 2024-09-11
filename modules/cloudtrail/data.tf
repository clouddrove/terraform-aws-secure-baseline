data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

#Data        : KMS
#Description : Terraform Data block to read an AWS IAM policy document for kms.
data "aws_iam_policy_document" "kms" {
  version = "2012-10-17"
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }
  statement {
    sid    = "Allow CloudTrail to encrypt logs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "Allow CloudTrail to describe key"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["kms:DescribeKey"]
    resources = ["*"]
  }

  statement {
    sid    = "Allow principals in the account to decrypt log files"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:ReEncryptFrom"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:*:${data.aws_caller_identity.current.account_id}:trail/*"]
    }
  }

  statement {
    sid    = "Allow alias creation during setup"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:CreateAlias"]
    resources = ["*"]
  }
}

#Data        : cloudwatch logs
#Description : Terraform Data block to read an AWS IAM policy document for Cloudtrail cloudwatch logs.
data "aws_iam_policy_document" "cloudtrail_cloudwatch_logs" {
  statement {
    sid = "WriteCloudWatchLogs"

    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    #tfsec:ignore:aws-iam-no-policy-wildcards
    resources = ["arn:${data.aws_partition.current.partition}:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:cloudwatch-log-group:*"]
  }
}

data "aws_iam_policy_document" "cloudwatch_delivery_policy" {
  count = var.enable_cloudwatch && var.enabled_cloudtrail ? 1 : 0
  statement {
    sid       = "AWSCloudTrailCreateLogStream2014110"
    actions   = ["logs:CreateLogStream"]
    resources = [format("arn:aws:logs:%s:%s:log-group:%s:log-stream:*", data.aws_region.current.name, data.aws_caller_identity.current.account_id, aws_cloudwatch_log_group.cloudtrail[0].name)]
  }
  statement {
    sid       = "AWSCloudTrailPutLogEvents20141101"
    actions   = ["logs:PutLogEvents"]
    resources = [format("arn:aws:logs:%s:%s:log-group:%s:log-stream:*", data.aws_region.current.name, data.aws_caller_identity.current.account_id, aws_cloudwatch_log_group.cloudtrail[0].name)]
  }
}


#Data        : Assume role for cloudtrail
#Description : Terraform Data block to read an AWS IAM policy document for Assumerole of cloudtrail.
data "aws_iam_policy_document" "cloudtrail_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

#Data        : S3 bucket policy
#Description : Terraform Data block to read an AWS IAM policy document for s3 bucket policy.
data "aws_iam_policy_document" "default" {
  statement {
    sid    = "cloudtrail-logs-get-bucket-acl"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:aws:s3:::${var.bucket_name}"]
  }

  statement {
    sid    = "cloudtrail-logs-put-object"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["arn:aws:s3:::${var.bucket_name}/AWSLogs/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}