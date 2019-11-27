output "cloudtrail_arn" {
  value       = module.cloudtrail.cloudtrail_arn
  description = "The Amazon Resource Name of the trail"
}

output "tags" {
  value       = module.cloudtrail.tags
  description = "A mapping of tags to assign to the Cloudtrail."
}
