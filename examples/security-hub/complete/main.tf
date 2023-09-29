## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

provider "aws" {
  region = "us-east-1"
}

module "security-hub" {
  source = "../../../modules/security_hub"

  security_hub_enabled = true

  #standards 
  enabled_standards = [
    "standards/aws-foundational-security-best-practices/v/1.0.0",
    "ruleset/cis-aws-foundations-benchmark/v/1.2.0"
  ]

  #products
  enabled_products = [
    "product/aws/guardduty",
    "product/aws/inspector"
  ]
}