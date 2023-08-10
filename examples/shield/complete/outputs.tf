output "id" {
  value       = module.aws_shield.*.id
  description = "The unique identifier (ID) for the Protection object that is created."
}

output "arn" {
  value       = module.aws_shield.*.arn
  description = "The unique identifier (ID) for the Protection object that is created."
}
