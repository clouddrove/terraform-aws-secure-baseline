## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "1.3.0"

  name        = var.name
  environment = var.environment
  label_order = var.label_order
  managedby   = var.managedby
}


resource "aws_shield_protection" "default" {
  count        = var.enabled ? length(var.resource_arn) : 0
  name         = format("%s-shield-%s", module.labels.id, count.index)
  resource_arn = var.resource_arn[count.index]
  tags         = module.labels.tags
}
