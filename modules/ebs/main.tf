## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.


resource "aws_ebs_encryption_by_default" "default" {
  count = var.enabled ? 1 : 0

  enabled = true
}