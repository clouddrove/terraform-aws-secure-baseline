provider "aws" {
  region = "eu-west-1"
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

module "secure_baseline" {
  source = "./../"

  application = "clouddrove"
  environment = "test"
  label_order = ["environment", "application", "name"]

  enabled                           = true
  key_deletion_window_in_days       = 10
  cloudwatch_logs_retention_in_days = 365
  cloudwatch_logs_group_name        = "cloudtrail-log-group"
  alarm_namespace                   = "Alert_Alarm"

  s3_bucket_name           = "cloudtrail-bucket-logs"
  config_s3_bucket_name    = "config-bucket"
  guardduty_s3_bucket_name = "guardduty-files"
  slack_webhook            = "https://hooks.slack.com/services/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uEG4TW"
  slack_channel            = "testing"
  s3_policy                = data.aws_iam_policy_document.default.json

  guardduty_enable        = true
  ipset_iplist            = ["10.10.0.0/16", "172.16.0.0/16", ]
  threatintelset_activate = false
  threatintelset_iplist   = ["192.168.2.0/32", "4.4.4.4", ]
}

data "aws_iam_policy_document" "default" {
  statement {
    sid = "AWSCloudTrailAclCheck"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = ["arn:aws:s3:::cloudtrail-bucket-logs"]
  }

  statement {
    sid = "AWSCloudTrailWrite"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = compact(
      concat(
        [format("arn:aws:s3:::cloudtrail-bucket-logs/AWSLogs/%s/*", data.aws_caller_identity.current.account_id)]
      )
    )

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}