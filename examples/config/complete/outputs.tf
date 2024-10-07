## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

output "configuration_recorder_id" {
  value       = module.config.configuration_recorder_id
  description = "The ID of configuration recorder."
}

output "configuration_recorder_arn" {
  value       = module.config.configuration_recorder_arn
  description = "The ARN of configuration recorder."
}

output "config_sns_id" {
  value       = module.config.config_sns_id
  description = "The SNS topic to which CloudWatch Alarms will be sent."
}
