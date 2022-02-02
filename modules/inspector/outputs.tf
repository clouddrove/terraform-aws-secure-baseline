output "resource_group" {
  value       = join("", aws_inspector_resource_group.default.*.arn)
  description = "The resource group ARN."
}

output "assessment_target" {
  value       = join("", aws_inspector_assessment_target.default.*.arn)
  description = "The target assessment ARN."
}

output "assessment_template" {
  value       = join("", aws_inspector_assessment_template.default.*.arn)
  description = "The template assessment ARN."
}

output "lambda_arn" {
  value       = module.lambda.arn
  description = "The Amazon Resource Name (ARN) identifying your Lambda Function."
}

output "tags" {
  value       = module.labels.tags
  description = "The tags of aws inspector."
}
