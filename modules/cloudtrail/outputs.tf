
output "cloudtrail_id" {
  value       = join("", aws_cloudtrail.default.*.id)
  description = "The name of the trail"
}

output "cloudtrail_arn" {
  value       = join("", aws_cloudtrail.default.*.arn)
  description = "The Amazon Resource Name of the trail"
}

output "cloudtrail_home_region" {
  value       = join("", aws_cloudtrail.default.*.home_region)
  description = "The region in which the trail was created."
}

output "log_group_name" {
  value       = join("", aws_cloudwatch_log_group.cloudtrail_events.*.name)
  description = "The CloudWatch Logs log group which stores CloudTrail events."
}

output "s3_id" {
  value       = module.s3_bucket.id
  description = "The Name of S3 bucket."
}

output "s3_arn" {
  value       = module.s3_bucket.arn
  description = "The ARN of S3 bucket."
}

output "kms_arn" {
  value       = module.kms_key.key_arn
  description = "The ARN of KMS key."
}

output "tags" {
  value       = module.labels.tags
  description = "A mapping of tags to assign to the resource."
}
