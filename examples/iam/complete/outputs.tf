## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

output "master_iam_role" {
  description = "The IAM role used for the master user."
  value       = module.iam-baseline.master_iam_role
}

output "manager_iam_role" {
  description = "The IAM role used for the manager user."
  value       = module.iam-baseline.manager_iam_role
}

output "support_iam_role" {
  description = "The IAM role used for the support user."
  value       = module.iam-baseline.support_iam_role
}
