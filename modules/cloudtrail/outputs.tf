
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
  value       = join("", aws_cloudwatch_log_group.cloudtrail.*.name)
  description = "The CloudWatch Logs log group which stores CloudTrail events."
}

output "s3_id" {
  value       = coalesce(join("", data.aws_s3_bucket.bucket.*.arn), module.s3_logs.arn)
  description = "The Name of S3 bucket."
}

output "kms_arn" {
  value       = join("", aws_kms_key.cloudtrail.*.id)
  description = "The ARN of KMS key."
}

output "tags" {
  value       = module.labels.tags
  description = "A mapping of tags to assign to the resource."
}
