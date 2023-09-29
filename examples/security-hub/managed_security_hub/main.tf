## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

module "security-hub" {
  source = "../../../modules/security_hub"

  security_hub_enabled = false
  master_account_id    = "112233445566" # Master ID of the account id of the Account where the security hub is available.

  # Id of the security hub in master account.
  security_hub_id = "123456789012"
  # Optional: ARN of the security hub in master account.
  security_hub_arn = "arn:aws:securityhub:us-east-1:112233445566:hub/default"
  # Note:
  #   To find the ARN for security hub you can run AWS command to get the details. e.g. aws securityhub describe-hub --query 'HubArn'

}