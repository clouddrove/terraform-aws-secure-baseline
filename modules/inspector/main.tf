## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_inspector_rules_packages" "rules" {}

#Module      : labels
#Description : Terraform module to create consistent naming for multiple names.
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "1.3.0"

  name        = var.name
  environment = var.environment
  enabled     = var.enabled
  managedby   = var.managedby
  label_order = var.label_order
}

#Module      : INSPECTOR RESOURCE GROUP
#Description : Match the instances with the below tags to attach to resource group.
resource "aws_inspector_resource_group" "default" {
  count = var.enabled ? 1 : 0
  tags  = var.instance_tags
}

#Module      : INSPECTOR ASSESSMENT TARGET
#Description : Attach the resource group to targets.
resource "aws_inspector_assessment_target" "default" {
  count              = var.enabled ? 1 : 0
  name               = format("%s-assessment-target", module.labels.id)
  resource_group_arn = join("", aws_inspector_resource_group.default.*.arn)
}

#Module      : INSPECTOR ASSESSMENT TEMPLATE
#Description : Creation of template and applying rule packages.
resource "aws_inspector_assessment_template" "default" {
  count              = var.enabled ? 1 : 0
  name               = format("%s-assessment-template", module.labels.id)
  target_arn         = join("", aws_inspector_assessment_target.default.*.arn)
  duration           = var.duration
  rules_package_arns = data.aws_inspector_rules_packages.rules.arns
  tags               = module.labels.tags
}

#Module      : CLOUD WATCH EVENT RULE
#Description : Event rule for cloud watch events.
resource "aws_cloudwatch_event_rule" "default" {
  count               = var.enabled ? 1 : 0
  name                = format("%s-assessment-er", module.labels.id)
  schedule_expression = var.schedule_expression
  description         = "Event rule for AWS Inspector assessment run."
  role_arn            = var.rule_iam_role_arn
  is_enabled          = var.is_enabled
  tags                = module.labels.tags
}

#Module      : CLOUD WATCH EVENT TARGET
#Description : Attaching event rule and lambda function to targets.
resource "aws_cloudwatch_event_target" "default" {
  count     = var.enabled && var.lambda_enabled ? 1 : 0
  rule      = join("", aws_cloudwatch_event_rule.default.*.name)
  target_id = "AssessmentRun"
  arn       = module.lambda.arn
  role_arn  = var.target_iam_role_arn

  depends_on = [
    module.lambda
  ]
}
#Module      : LAMBDA
#Description : Creating a lambda function for assessment run.
module "lambda" {
  source  = "clouddrove/lambda/aws"
  version = "1.3.0"

  name          = var.name
  environment   = var.environment
  label_order   = var.label_order
  enabled       = var.enabled
  iam_actions   = var.iam_actions
  filename      = format("%s/assessment", path.module)
  handler       = var.handler
  runtime       = var.runtime
  timeout       = var.timeout
  kms_key_arn   = var.kms_key_id
  statement_ids = var.statement_ids
  actions       = var.actions
  principals    = var.principals
  source_arns   = [join("", aws_cloudwatch_event_rule.default.*.arn)]

  variables = {
    assessmentTemplateArn = join("", aws_inspector_assessment_template.default.*.arn)
  }
}
