## Managed By : CloudDrove
## Copyright @ CloudDrove. All Right Reserved.

data "aws_caller_identity" "current" {}

#Module      : Label
#Description : This terraform module is designed to generate consistent label names and
#              tags for resources. You can use terraform-labels to implement a strict
#              naming convention
module "labels" {
  source  = "clouddrove/labels/aws"
  version = "0.15.0"

  name        = var.name
  environment = var.environment
  label_order = var.label_order
  managedby   = var.managedby
}

resource "null_resource" "cluster" {
  count = var.enabled ? 1 : 0
  provisioner "local-exec" {
    command = format("cd %s/slack && bash build.sh", path.module)
  }
}

module "alarm-lambda" {
  source  = "clouddrove/lambda/aws"
  version = "0.15.0"

  name        = "alarm-lambda"
  environment = var.environment
  label_order = var.label_order
  enabled     = var.enabled
  managedby   = var.managedby

  filename = format("%s/slack/src", path.module)
  handler  = "index.lambda_handler"
  runtime  = "python3.8"
  iam_actions = [
    "logs:CreateLogStream",
    "logs:CreateLogGroup",
    "logs:PutLogEvents",
    "sns:ListTopics",
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
    "AllowExecutionFromSNS"
  ]
  actions = [
    "lambda:InvokeFunction"
  ]
  principals = [
    "sns.amazonaws.com"
  ]
  source_arns = [module.sns.topic-arn]
  variables   = var.variables
}

#Module      : SNS
#Description : Provides an SNS topic resource
module "sns" {
  source  = "clouddrove/sns/aws"
  version = "0.15.0"

  name         = "alarm-sns"
  environment  = var.environment
  label_order  = var.label_order
  managedby    = var.managedby
  enable_topic = true
  enabled      = var.enabled

  protocol        = "lambda"
  endpoint        = module.alarm-lambda.arn
  delivery_policy = format("%s/_json/delivery_policy.json", path.module)
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  count = var.enabled && var.unauthorized_api_calls ? 1 : 0

  name           = "UnauthorizedAPICalls"
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
  log_group_name = var.cloudtrail_log_group_name
  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  count = var.enabled && var.unauthorized_api_calls ? 1 : 0

  alarm_name                = "UnauthorizedAPICalls"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.unauthorized_api_calls.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring unauthorized API calls will help reveal application errors and may reduce time to detect malicious activity."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "no_mfa_console_signin" {
  count = var.enabled && var.no_mfa_console_signin ? 1 : 0

  name           = "NoMFAConsoleSignin"
  pattern        = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NoMFAConsoleSignin"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "no_mfa_console_signin" {
  count = var.enabled && var.no_mfa_console_signin ? 1 : 0

  alarm_name                = "NoMFAConsoleSignin"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.no_mfa_console_signin.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for single-factor console logins will increase visibility into accounts that are not protected by MFA."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  count = var.enabled && var.root_usage ? 1 : 0

  name           = "RootUsage"
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "RootUsage"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "root_usage" {
  count = var.enabled && var.root_usage ? 1 : 0

  alarm_name                = "RootUsage"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.root_usage.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring for root account logins will provide visibility into the use of a fully privileged account and an opportunity to reduce the use of it."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  count = var.enabled && var.iam_changes ? 1 : 0

  name           = "IAMChanges"
  pattern        = "{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "IAMChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  count = var.enabled && var.iam_changes ? 1 : 0

  alarm_name                = "IAMChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.iam_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to IAM policies will help ensure authentication and authorization controls remain intact."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "cloudtrail_cfg_changes" {
  count = var.enabled && var.cloudtrail_cfg_changes ? 1 : 0

  name           = "CloudTrailCfgChanges"
  pattern        = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "CloudTrailCfgChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "cloudtrail_cfg_changes" {
  count = var.enabled && var.cloudtrail_cfg_changes ? 1 : 0

  alarm_name                = "CloudTrailCfgChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.cloudtrail_cfg_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to CloudTrail's configuration will help ensure sustained visibility to activities performed in the AWS account."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "console_signin_failures" {
  count = var.enabled && var.console_signin_failures ? 1 : 0

  name           = "ConsoleSigninFailures"
  pattern        = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "ConsoleSigninFailures"
    namespace = var.alarm_namespace
    value     = "1"
  }
}


#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "console_signin_failures" {
  count = var.enabled && var.console_signin_failures ? 1 : 0

  alarm_name                = "ConsoleSigninFailures"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.console_signin_failures.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "disable_or_delete_cmk" {
  count = var.enabled && var.disable_or_delete_cmk ? 1 : 0

  name           = "DisableOrDeleteCMK"
  pattern        = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "DisableOrDeleteCMK"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource
resource "aws_cloudwatch_metric_alarm" "disable_or_delete_cmk" {
  count = var.enabled && var.disable_or_delete_cmk ? 1 : 0

  alarm_name                = "DisableOrDeleteCMK"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.disable_or_delete_cmk.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring failed console logins may decrease lead time to detect an attempt to brute force a credential, which may provide an indicator, such as source IP, that can be used in other event correlation."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "s3_bucket_policy_changes" {
  count = var.enabled && var.s3_bucket_policy_changes ? 1 : 0

  name           = "S3BucketPolicyChanges"
  pattern        = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "S3BucketPolicyChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource
resource "aws_cloudwatch_metric_alarm" "s3_bucket_policy_changes" {
  count = var.enabled && var.s3_bucket_policy_changes ? 1 : 0

  alarm_name                = "S3BucketPolicyChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.s3_bucket_policy_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to S3 bucket policies may reduce time to detect and correct permissive policies on sensitive S3 buckets."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "security_group_changes" {
  count = var.enabled && var.security_group_changes ? 1 : 0

  name           = "SecurityGroupChanges"
  pattern        = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "SecurityGroupChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "security_group_changes" {
  count = var.enabled && var.security_group_changes ? 1 : 0

  alarm_name                = "SecurityGroupChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.security_group_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to security group will help ensure that resources and services are not unintentionally exposed."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "nacl_changes" {
  count = var.enabled && var.nacl_changes ? 1 : 0

  name           = "NACLChanges"
  pattern        = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NACLChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "nacl_changes" {
  count = var.enabled && var.nacl_changes ? 1 : 0

  alarm_name                = "NACLChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.nacl_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to NACLs will help ensure that AWS resources and services are not unintentionally exposed."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}


#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "network_gw_changes" {
  count = var.enabled && var.network_gw_changes ? 1 : 0

  name           = "NetworkGWChanges"
  pattern        = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "NetworkGWChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "network_gw_changes" {
  count = var.enabled && var.network_gw_changes ? 1 : 0

  alarm_name                = "NetworkGWChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.network_gw_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to network gateways will help ensure that all ingress/egress traffic traverses the VPC border via a controlled path."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatchLog Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "route_table_changes" {
  count = var.enabled && var.route_table_changes ? 1 : 0

  name           = "RouteTableChanges"
  pattern        = "{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "RouteTableChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "route_table_changes" {
  count = var.enabled && var.route_table_changes ? 1 : 0

  alarm_name                = "RouteTableChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.route_table_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to route tables will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []

  tags = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "vpc_changes" {
  count = var.enabled && var.vpc_changes ? 1 : 0

  name           = "VPCChanges"
  pattern        = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "VPCChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "vpc_changes" {
  count = var.enabled && var.vpc_changes ? 1 : 0

  alarm_name                = "VPCChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.vpc_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to VPC will help ensure that all VPC traffic flows through an expected path."
  alarm_actions             = [module.sns.topic-arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = module.labels.tags
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_FILTER
#Description : Provides a CloudWatch Log Metric Filter resource.
resource "aws_cloudwatch_log_metric_filter" "aws_config_changes" {
  count = var.enabled && var.aws_config_changes_enabled ? 1 : 0

  name           = "AWSConfigChanges"
  pattern        = "{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.eventName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }"
  log_group_name = var.cloudtrail_log_group_name

  metric_transformation {
    name      = "AWSConfigChanges"
    namespace = var.alarm_namespace
    value     = "1"
  }
}

#Module      : AWS_CLOUDWATCH_LOG_METRIC_ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
resource "aws_cloudwatch_metric_alarm" "aws_config_changes" {
  count = var.enabled && var.aws_config_changes_enabled ? 1 : 0

  alarm_name                = "AWSConfigChanges"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  metric_name               = join("", aws_cloudwatch_log_metric_filter.vpc_changes.*.id)
  namespace                 = var.alarm_namespace
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "1"
  alarm_description         = "Monitoring changes to AWS Config configuration will help ensure sustained visibility of configuration items within the AWS account."
  alarm_actions             = [aws_sns_topic.alarms[0].arn]
  treat_missing_data        = "notBreaching"
  insufficient_data_actions = []
  tags                      = module.labels.tags

}
