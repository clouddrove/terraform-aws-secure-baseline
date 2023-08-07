provider "aws" {
  region = "us-east-1"
}

module "guardduty" {
  source = "../../../modules/guardduty"

  name         = "test-guardduty"
  label_order  = ["name"]
  enabled      = true
  ipset_iplist = ["10.10.0.0/16"]

  finding_publishing_frequency = "ONE_HOUR"

  # S3
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  organization_auto_enable = false

  # Slack Alerts
  slack_enabled = false # Pass true to enable lambda
}