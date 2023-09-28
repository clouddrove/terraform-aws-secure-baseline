output "id" {
  value       = join("", aws_shield_protection.default[*].id)
  description = "The unique identifier (ID) for the Protection object that is created."
}

output "arn" {
  value       = join("", aws_shield_protection.default[*].arn)
  description = "The unique identifier (ID) for the Protection object that is created."
}
