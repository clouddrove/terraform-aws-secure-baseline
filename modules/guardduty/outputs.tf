output "detector_id" {
  value       = join("", aws_guardduty_detector.detector[*].id)
  description = "The ID of the GuardDuty detector"
}

output "account_id" {
  value       = join("", aws_guardduty_detector.detector[*].account_id)
  description = "The AWS account ID of the GuardDuty detector"
}

output "tags" {
  value       = module.labels.tags
  description = "The tags of aws inspector."
}
