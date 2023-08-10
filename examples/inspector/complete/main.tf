## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_caller_identity" "current" {}

provider "aws" {
  region = "us-east-1"
}

module "inspector" {
  source = "../../../modules/inspector"

  ## Tags
  name        = "inspector"
  environment = "security"
  label_order = ["name", "environment"]
  enabled     = true

  instance_tags = {
    "Inspector" = true
  }

  duration            = 300
  lambda_enabled      = true
  schedule_expression = "cron(0/10 * ? * * *)"
  handler             = "index.handler"
  runtime             = "nodejs18.x"
  statement_ids       = ["AllowExecutionFromEvents"]
  actions             = ["lambda:InvokeFunction"]
  principals          = ["events.amazonaws.com"]

  iam_actions = [
    "inspector:StartAssessmentRun",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:PutLogEvents"
  ]
}