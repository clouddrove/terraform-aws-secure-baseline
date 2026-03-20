## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

output "resource_group" {
  value       = module.inspector.resource_group
  description = "The resource group ARN."
}

output "assessment_target" {
  value       = module.inspector.assessment_target
  description = "The target assessment ARN."
}

output "assessment_template" {
  value       = module.inspector.assessment_template
  description = "The template assessment ARN."
}

output "lambda_arn" {
  value       = module.inspector.lambda_arn
  description = "The Amazon Resource Name (ARN) identifying your Lambda Function."
}
