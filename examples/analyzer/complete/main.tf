## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

#Module      : Analyzer
#Description : This module helps you identify the resources in your organization and accounts, such as Amazon S3 buckets or IAM roles, shared with an external entity.
module "analyzer" {
  source = "../../../modules/analyzer"

  name        = "analyzer"
  environment = "test"
  label_order = ["name", "environment"]
  enabled     = true

  ## IAM Access Analyzer
  type = "ACCOUNT"

  variables = {
    slack_webhook = "" # Webhook for the slack notification
    slack_channel = "" # Channel of the Slack where the notification will receive
  }
}
