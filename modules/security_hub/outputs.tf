#Module      : Security-hub
#Description : Terraform module to securitry hub outputs.
output "id" {
  value       = aws_securityhub_account.security_hub[0].id
  description = "The ID of the secuirty hub."
}