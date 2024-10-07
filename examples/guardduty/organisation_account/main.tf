## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

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

  is_guardduty_member      = false
  organization_auto_enable = true
  guardduty_admin_id       = "112233445566" # Delegated account id that will be centralised guardduty administrator for all guardduty accounts

  datasources = {
    s3_logs                = false,
    kubernetes_audit_logs  = true,
    malware_protection_ebs = true
  }

  # Organization member accounts
  member_list = [
    {
      account_id = "333333333333", # Member account id of the organization member account
      invite     = true,
      email      = "email@example.com"
    },
    # {
    #   account_id = "222222222222" # Member account id of the organization member account
    #   invite     = true,
    #   email      = "email@example.com"
    # }
  ]

  # Slack Alerts
  slack_enabled = false # Pass true to enable lambda
}
