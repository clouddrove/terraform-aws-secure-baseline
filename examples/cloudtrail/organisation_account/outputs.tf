output "cloudtrail_arn" {
    value       = module.cloudtrail.*.cloudtrail_arn
    description = "The Amazon Resource Name of the trail."
}

output "cloudtrail_s3_id" {
    value       = try(module.cloudtrail.s3_id, "")
    description = "The Name of S3 bucket for logging of Cloudtrail."
}