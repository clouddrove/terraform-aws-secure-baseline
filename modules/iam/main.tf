# Managed By : CloudDrove
# Description : This Script is used to create EC2, EIP, EBS VOLUME,  and VOLUME ATTACHMENT.
# Copyright @ CloudDrove. All Right Reserved.

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention.
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "0.15.0"

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

data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "master_assume_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "master" {
  count              = var.enabled  ? 1 : 0
  name               = var.master_iam_role_name
  assume_role_policy = data.aws_iam_policy_document.master_assume_policy.json
  tags               = module.labels.tags
}

data "aws_iam_policy_document" "master_policy" {
  statement {
    actions = [
      "iam:CreateGroup", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:CreateRole", "iam:CreateUser",
      "iam:DeleteGroup", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DeleteUser",
      "iam:PutRolePolicy",
      "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetRolePolicy", "iam:GetUser", "iam:GetUserPolicy",
      "iam:ListEntitiesForPolicy", "iam:ListGroupPolicies", "iam:ListGroups", "iam:ListGroupsForUser",
      "iam:ListPolicies", "iam:ListPoliciesGrantingServiceAccess", "iam:ListPolicyVersions",
      "iam:ListRolePolicies", "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies", "iam:ListRoles", "iam:ListUsers"
    ]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:AddUserToGroup",
      "iam:AttachGroupPolicy",
      "iam:DeleteGroupPolicy", "iam:DeleteUserPolicy",
      "iam:DetachGroupPolicy", "iam:DetachRolePolicy", "iam:DetachUserPolicy",
      "iam:PutGroupPolicy", "iam:PutUserPolicy",
      "iam:RemoveUserFromGroup",
      "iam:UpdateGroup", "iam:UpdateAssumeRolePolicy", "iam:UpdateUser"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "master_policy" {
  count  = var.enabled  ? 1 : 0
  name   = var.master_iam_role_policy_name
  role   = join("", aws_iam_role.master.*.id)
  policy = data.aws_iam_policy_document.master_policy.json
}

data "aws_iam_policy_document" "manager_assume_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "manager" {
  count              = var.enabled  ? 1 : 0
  name               = var.manager_iam_role_name
  assume_role_policy = data.aws_iam_policy_document.manager_assume_policy.json
  tags               = module.labels.tags
}

data "aws_iam_policy_document" "manager_policy" {
  statement {
    actions = [
      "iam:AddUserToGroup",
      "iam:AttachGroupPolicy",
      "iam:DeleteGroupPolicy", "iam:DeleteUserPolicy",
      "iam:DetachGroupPolicy", "iam:DetachRolePolicy", "iam:DetachUserPolicy",
      "iam:PutGroupPolicy", "iam:PutUserPolicy",
      "iam:RemoveUserFromGroup",
      "iam:UpdateGroup", "iam:UpdateAssumeRolePolicy", "iam:UpdateUser",
      "iam:GetPolicy", "iam:GetPolicyVersion", "iam:GetRole", "iam:GetRolePolicy", "iam:GetUser", "iam:GetUserPolicy",
      "iam:ListEntitiesForPolicy", "iam:ListGroupPolicies", "iam:ListGroups", "iam:ListGroupsForUser",
      "iam:ListPolicies", "iam:ListPoliciesGrantingServiceAccess", "iam:ListPolicyVersions",
      "iam:ListRolePolicies", "iam:ListAttachedGroupPolicies", "iam:ListAttachedRolePolicies",
      "iam:ListAttachedUserPolicies", "iam:ListRoles", "iam:ListUsers"
    ]
    resources = ["*"]
    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }

  statement {
    effect = "Deny"
    actions = [
      "iam:CreateGroup", "iam:CreatePolicy", "iam:CreatePolicyVersion", "iam:CreateRole", "iam:CreateUser",
      "iam:DeleteGroup", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DeleteUser",
      "iam:PutRolePolicy"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "manager_policy" {
  count  = var.enabled  ? 1 : 0
  name   = var.manager_iam_role_policy_name
  role   = join("", aws_iam_role.manager.*.id)
  policy = data.aws_iam_policy_document.manager_policy.json
}

# --------------------------------------------------------------------------------------------------
# Support Role
# --------------------------------------------------------------------------------------------------
data "aws_iam_policy_document" "support_assume_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [var.support_iam_role_principal_arn]
    }
    actions = ["sts:AssumeRole"]
  }
}

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
