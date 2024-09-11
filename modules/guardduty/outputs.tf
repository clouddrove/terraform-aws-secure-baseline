output "detector_id" {
  value       = join("", aws_guardduty_detector.detector.*.id)
  description = "The ID of the GuardDuty detector"
}

output "account_id" {
  value       = join("", aws_guardduty_detector.detector.*.account_id)
  description = "The AWS account ID of the GuardDuty detector"
}

output "tags" {
  value       = module.labels.tags
  description = "The tags of aws inspector."
}


# S3 Bucket

output "bucket_id" {
  value       = local.bucket_name
  description = "The bucket id of S3 for guardduty logs."
}