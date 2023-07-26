output "cloudtrail_arn" {
  value       = module.cloudtrail.*.cloudtrail_arn
  description = "The Amazon Resource Name of the trail."
}