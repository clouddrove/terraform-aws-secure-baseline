## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_caller_identity" "current" {}

provider "aws" {
  region = "us-east-1"
}

module "iam-baseline" {
  source = "../../../modules/iam"

  name        = "iam-baseline"
  environment = "test"
  label_order = ["name", "environment"]
  enabled     = true

  master_iam_role_name           = "IAM-Master"
  master_iam_role_policy_name    = "IAM-master-Policy"
  manager_iam_role_name          = "IAM-manager"
  manager_iam_role_policy_name   = "IAM-Manager-Policy"
  support_iam_role_name          = "IAM-Policy"
  support_iam_role_principal_arn = data.aws_caller_identity.current.arn
}