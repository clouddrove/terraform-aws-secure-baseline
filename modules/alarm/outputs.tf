
output "alarm_sns_id" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = var.enabled ? module.sns.topic-id : null
}

output "alarm_sns_arn" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = var.enabled ? module.sns.topic-arn : null
}
output "tags" {
  value       = module.labels.tags
  description = "A mapping of tags to assign to the resource."
}

output "lambda_arn" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = var.enabled ? module.alarm-lambda.arn : null
}