#Module      : Security-hub
#Description : Terraform module to securitry hub outputs.
output "id" {
  value       = try( aws_securityhub_account.security_hub[0].id, var.security_hub_id )
  description = "The ID of the secuirty hub deployed in the master account."
}

output "arn" {
  value       = try( aws_securityhub_account.security_hub[0].arn, var.security_hub_arn )
  description = "The ARN of the secuirty hub deployed in the master account."
}