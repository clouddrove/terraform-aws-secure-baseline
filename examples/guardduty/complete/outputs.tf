## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

output "detector_id" {
  value       = module.guardduty.detector_id
  description = "The ID of the GuardDuty detector"
}

output "account_id" {
  value       = module.guardduty.account_id
  description = "The AWS account ID of the GuardDuty detector"
}

output "s3_bucket_id" {
  value       = module.guardduty.bucket_id
  description = "The bucket id of S3 for guardduty logs."
}
