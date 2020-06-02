output "configuration_recorder_id" {
  value       = join("", aws_config_configuration_recorder.recorder.*.id)
  description = "The ID of configuration recorder."
}

output "configuration_recorder_arn" {
  value       = join("", aws_config_configuration_recorder.recorder.*.role_arn)
  description = "The ARN of configuration recorder."
}

output "config_sns_id" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = module.sns.topic-id
}

output "config_sns_arn" {
  description = "The SNS topic to which CloudWatch Alarms will be sent."
  value       = module.sns.topic-arn
}
output "tags" {
  value       = module.labels.tags
  description = "A mapping of tags to assign to the resource."
}