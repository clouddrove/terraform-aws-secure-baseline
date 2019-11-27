output "cloudtrail_arn" {
  value       = module.secure_baseline.*.cloudtrail_arn
  description = "The Amazon Resource Name of the trail"
}

output "tags" {
  value       = module.secure_baseline.tags
  description = "A mapping of tags to assign to the Cloudtrail."
}