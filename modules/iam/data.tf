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

data "aws_iam_policy_document" "manager_assume_policy" {
  statement {
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions = ["sts:AssumeRole"]
  }
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
