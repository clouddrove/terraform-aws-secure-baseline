## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.
output "alarm_sns_arn" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = module.alarm.alarm_sns_arn
}

output "lambda_arn" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = module.alarm.lambda_arn
}