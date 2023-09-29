## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

#Module      : Security-hub
#Description : Terraform module to securitry hub outputs.
output "id" {
  value       = module.security-hub.id
  description = "The ID of the secuirty hub."
}

output "arn" {
  value       = module.security-hub.arn
  description = "The ID of the secuirty hub."
}