#Module      : Security-hub
#Description : Terraform module to securitry hub outputs.
output "id" {
  value       = aws_securityhub_account.security_hub[0].id
  description = "The ID of the secuirty hub."
}

output "arn" {
  value       = aws_securityhub_account.security_hub[0].arn
  description = "The ID of the secuirty hub."
}