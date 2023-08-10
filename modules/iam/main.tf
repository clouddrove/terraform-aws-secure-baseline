# Managed By : CloudDrove
# Description : This Script is used to create EC2, EIP, EBS VOLUME,  and VOLUME ATTACHMENT.
# Copyright @ CloudDrove. All Right Reserved.

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention.
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "1.3.0"

  name        = var.name
  repository  = var.repository
  environment = var.environment
  label_order = var.label_order
}

resource "aws_iam_account_password_policy" "default" {
  count                          = var.aws_iam_account_password_policy ? 1 : 0
  minimum_password_length        = var.minimum_password_length
  password_reuse_prevention      = var.password_reuse_prevention
  require_lowercase_characters   = var.require_lowercase_characters
  require_numbers                = var.require_numbers
  require_uppercase_characters   = var.require_uppercase_characters
  require_symbols                = var.require_symbols
  allow_users_to_change_password = var.allow_users_to_change_password
  max_password_age               = var.max_password_age
}

# --------------------------------------------------------------------------------------------------
# Manager & Master Role Separation
# --------------------------------------------------------------------------------------------------

resource "aws_iam_role" "master" {
  count              = var.enabled ? 1 : 0
  name               = var.master_iam_role_name
  assume_role_policy = data.aws_iam_policy_document.master_assume_policy.json
  tags               = module.labels.tags
}

resource "aws_iam_role_policy" "master_policy" {
  count  = var.enabled ? 1 : 0
  name   = var.master_iam_role_policy_name
  role   = join("", aws_iam_role.master.*.id)
  policy = data.aws_iam_policy_document.master_policy.json
}

resource "aws_iam_role" "manager" {
  count              = var.enabled ? 1 : 0
  name               = var.manager_iam_role_name
  assume_role_policy = data.aws_iam_policy_document.manager_assume_policy.json
  tags               = module.labels.tags
}

resource "aws_iam_role_policy" "manager_policy" {
  count  = var.enabled ? 1 : 0
  name   = var.manager_iam_role_policy_name
  role   = join("", aws_iam_role.manager.*.id)
  policy = data.aws_iam_policy_document.manager_policy.json
}

# --------------------------------------------------------------------------------------------------
# Support Role
# --------------------------------------------------------------------------------------------------

resource "aws_iam_role" "support" {
  count              = var.enabled ? 1 : 0
  name               = var.support_iam_role_name
  assume_role_policy = data.aws_iam_policy_document.support_assume_policy.json

  tags = module.labels.tags
}

resource "aws_iam_role_policy_attachment" "support_policy" {
  count      = var.enabled ? 1 : 0
  role       = join("", aws_iam_role.support.*.id)
  policy_arn = "arn:aws:iam::aws:policy/AWSSupportAccess"
}
