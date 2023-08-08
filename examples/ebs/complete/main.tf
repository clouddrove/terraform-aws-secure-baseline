provider "aws" {
  region = "us-east-1"
}

module "ebs" {
  source = "../../../modules/ebs"

  enabled                       = true
  enable_default_ebs_encryption = true
}