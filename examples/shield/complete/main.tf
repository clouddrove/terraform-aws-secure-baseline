provider "aws" {
  region = "us-east-1"
}

module "aws_shield" {
  source = "../../../modules/shield"

  name        = "shield"
  environment = "security"
  label_order = ["name", "environment"]
  enabled     = false

  ## AWS SHIELD
  resource_arn = [] # ARN of the Resource that needs to be protect with Shield. e.g. cloudfront, ALB, EIP, Route53 etc.

}