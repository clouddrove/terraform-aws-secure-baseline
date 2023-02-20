## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

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

#Module      : CLOUD WATCH EVENT RULE
#Description : Event rule for cloud watch events.
resource "aws_cloudwatch_event_rule" "default" {
  count       = var.enabled ? 1 : 0
  name        = format("%s-er", module.labels.id)
  description = "Event rule for AWS IAM Access Analyzer."
  role_arn    = var.rule_iam_role_arn
  is_enabled  = var.enabled
  tags        = module.labels.tags

  event_pattern = <<PATTERN
  {
    "source": [
      "aws.access-analyzer"
    ],
    "detail-type": [
      "Access Analyzer Finding"
    ]
  }
  PATTERN
}

#Module      : CLOUD WATCH EVENT TARGET
#Description : Attaching event rule and lambda function to targets.
resource "aws_cloudwatch_event_target" "default" {
  count     = var.enabled ? 1 : 0
  rule      = join("", aws_cloudwatch_event_rule.default.*.name)
  target_id = "IAMAccessAnalyzer"
  arn       = module.slack-lambda.arn # ARN of the Lambda Function, write after including lambda function
  role_arn  = var.target_iam_role_arn
}

resource "null_resource" "cluster" {
  count = var.enabled ? 1 : 0
  provisioner "local-exec" {
    command = format("cd %s/slack && bash build.sh", path.module)
  }
}

module "slack-lambda" {
  source  = "clouddrove/lambda/aws"
  version = "1.3.0"

  name        = format("%s-slack-lambda", module.labels.id)
  environment = var.environment
  label_order = ["name"]
  managedby   = var.managedby
  enabled     = var.enabled

  filename = format("%s/slack/src", path.module)
  handler  = "index.lambda_handler"
  runtime  = "python3.8"
  iam_actions = [
    "logs:CreateLogStream",
    "logs:CreateLogGroup",
    "logs:PutLogEvents",
    "event:*",
  ]
  timeout = 30

  names = [
    "python_layer"
  ]
  layer_filenames = [format("%s/slack/packages/Python3-slack.zip", path.module)]
  compatible_runtimes = [
    ["python3.8"]
  ]

  statement_ids = [
    "AllowExecutionFromCloudWatch"
  ]
  actions = [
    "lambda:InvokeFunction"
  ]
  principals = [
    "events.amazonaws.com"
  ]
  source_arns = [join("", aws_cloudwatch_event_rule.default.*.arn)]
  variables   = var.variables
}

resource "null_resource" "default" {
  count = var.enabled ? 1 : 0
  provisioner "local-exec" {
    command = "sleep 200"
  }
}

#Module      : IAM ACCESS ANALYZER
#Description : Terraform resource to create an iam access analyzer.

resource "aws_accessanalyzer_analyzer" "default" {
  count         = var.enabled ? 1 : 0
  analyzer_name = module.labels.id
  tags          = module.labels.tags
  type          = var.type
  depends_on = [
    null_resource.default,
  ]
}
