output "analyzer_name" {
  value       = join("", aws_accessanalyzer_analyzer.default.*.id)
  description = "Analyzer name."
}

output "tags" {
  value       = module.labels.tags
  description = "The tags of the iam access analyzer."
}