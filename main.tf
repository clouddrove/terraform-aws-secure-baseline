
#Module      : CLOUDTRAIL
#Description : Terraform module to provision an AWS CloudTrail with encrypted S3 bucket.
#              This bucket is used to store CloudTrail logs.
module "cloudtrail" {
  source                            = "./modules/cloudtrail"
  name                              = "trails"
  application                       = var.application
  environment                       = var.environment
  managedby                         = var.managedby
  label_order                       = var.label_order
  enabled                           = var.enabled && var.cloudtrail_enabled
  iam_role_name                     = "CloudTrail-CloudWatch-Delivery-Role"
  iam_role_policy_name              = "CloudTrail-CloudWatch-Delivery-Policy"
  account_type                      = "individual"
  key_deletion_window_in_days       = var.key_deletion_window_in_days
  cloudwatch_logs_retention_in_days = var.cloudwatch_logs_retention_in_days
  cloudwatch_logs_group_name        = var.cloudwatch_logs_group_name
  EVENT_IGNORE_LIST                 = jsonencode(["^Describe*", "^Assume*", "^List*", "^Get*", "^Decrypt*", "^Lookup*", "^BatchGet*", "^CreateLogStream$", "^RenewRole$", "^REST.GET.OBJECT_LOCK_CONFIGURATION$", "TestEventPattern", "TestScheduleExpression", "CreateNetworkInterface", "ValidateTemplate"])
  EVENT_ALERT_LIST                  = jsonencode(["DetachRolePolicy", "ConsoleLogin"])
  USER_IGNORE_LIST                  = jsonencode(["^awslambda_*", "^aws-batch$", "^bamboo*", "^i-*", "^[0-9]*$", "^ecs-service-scheduler$", "^AutoScaling$", "^AWSCloudFormation$", "^CloudTrailBot$", "^SLRManagement$"])
  SOURCE_LIST                       = jsonencode(["aws-sdk-go"])
  s3_bucket_name                    = var.cloudtrail_bucket_name
  slack_webhook                     = var.slack_webhook
  slack_channel                     = var.slack_channel
  s3_policy                         = var.cloudtrail_s3_policy
}

#Module      : ALARM
#Description : Provides a CloudWatch Metric Alarm resource.
module "alarm" {
  source      = "./modules/alarm"
  name        = "alarm"
  application = var.application
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order

  enabled                  = var.enabled && var.alarm_enabled
  unauthorized_api_calls   = var.unauthorized_api_calls
  no_mfa_console_signin    = var.no_mfa_console_signin
  root_usage               = var.root_usage
  iam_changes              = var.iam_changes
  cloudtrail_cfg_changes   = var.cloudtrail_cfg_changes
  console_signin_failures  = var.console_signin_failures
  disable_or_delete_cmk    = var.disable_or_delete_cmk
  s3_bucket_policy_changes = var.s3_bucket_policy_changes
  security_group_changes   = var.security_group_changes
  nacl_changes             = var.nacl_changes
  network_gw_changes       = var.network_gw_changes
  route_table_changes      = var.route_table_changes
  vpc_changes              = var.vpc_changes
  alarm_namespace          = var.alarm_namespace

  cloudtrail_log_group_name = module.cloudtrail.log_group_name
  variables = {
    SLACK_WEBHOOK = var.slack_webhook
    SLACK_CHANNEL = var.slack_channel
  }
}

#Module      : CONFIG BASELINE
#Description : Manages status (recording / stopped) of an AWS Config Configuration Recorder.
module "config" {
  source                = "./modules/config"
  name                  = "config"
  application           = var.application
  environment           = var.environment
  label_order           = var.label_order
  managedby             = var.managedby
  enabled               = var.enabled && var.config_enabled
  only_config_enabled   = var.only_config_enabled
  config_role_arn       = var.config_role_arn
  config_s3_bucket_name = var.config_s3_bucket_name
  target_config_bucket  = var.target_config_bucket
  target_config_prefix  = var.target_config_prefix
  sse_algorithm         = var.sse_algorithm
  tracing_mode          = var.tracing_mode
  attach_tracing_policy = var.attach_tracing_policy

  # roles
  restricted_ports                   = var.restricted_ports
  restricted_ports_list              = var.restricted_ports_list
  iam_mfa                            = var.iam_mfa
  unused_credentials                 = var.unused_credentials
  user_no_policies                   = var.user_no_policies
  no_policies_with_full_admin_access = var.no_policies_with_full_admin_access
  acm_certificate_expiration_check   = var.acm_certificate_expiration_check
  ec2_volume_inuse_check             = var.ec2_volume_inuse_check
  ebs_snapshot_public_restorable     = var.ebs_snapshot_public_restorable
  rds_instance_public_access_check   = var.rds_instance_public_access_check
  rds_snapshots_public_prohibited    = var.rds_snapshots_public_prohibited
  guardduty_enabled_centralized      = var.guardduty_enabled_centralized
  s3_bucket_public_write_prohibited  = var.s3_bucket_public_write_prohibited
  eip_attached                       = var.eip_attached
  ec2_encrypted_volumes              = var.ec2_encrypted_volumes
  iam_root_access_key                = var.iam_root_access_key
  vpc_default_security_group_closed  = var.vpc_default_security_group_closed
  s3_bucket_ssl_requests_only        = var.s3_bucket_ssl_requests_only
  multi_region_cloudtrail_enabled    = var.multi_region_cloudtrail_enabled
  instances_in_vpc                   = var.instances_in_vpc
  cloudwatch_log_group_encrypted     = var.cloudwatch_log_group_encrypted
  rds_storage_encrypted              = var.rds_storage_encrypted

  iam_password_policy                                     = var.iam_password_policy
  password_require_uppercase                              = var.password_require_uppercase
  password_require_lowercase                              = var.password_require_lowercase
  password_require_symbols                                = var.password_require_symbols
  password_require_numbers                                = var.password_require_numbers
  password_min_length                                     = var.password_min_length
  password_reuse_prevention                               = var.password_reuse_prevention
  password_max_age                                        = var.password_max_age
  Access_keys_rotated                                     = var.Access_keys_rotated
  Access_keys_rotated_value                               = var.Access_keys_rotated_value
  Account_part_of_organization                            = var.Account_part_of_organization
  alb_http_drop_invalid_header_enabled                    = var.alb_http_drop_invalid_header_enabled
  alb_http_to_https_redirection_check                     = var.alb_http_to_https_redirection_check
  alb_waf_enabled                                         = var.alb_waf_enabled
  api_gw_associated_with_waf                              = var.api_gw_associated_with_waf
  api_gw_cache_enabled_and_encrypted                      = var.api_gw_cache_enabled_and_encrypted
  api_gw_endpoint_type_check                              = var.api_gw_endpoint_type_check
  api_gw_endpoint_type_check_value                        = var.api_gw_endpoint_type_check_value
  api_gw_execution_logging_enable                         = var.api_gw_execution_logging_enable
  api_gw_ssl_enabled                                      = var.api_gw_ssl_enabled
  api_gw_xray_enabled                                     = var.api_gw_xray_enabled
  approved_aims_by_id                                     = var.approved_aims_by_id
  approved_aims_by_id_value                               = var.approved_aims_by_id_value
  approved_aims_by_tag                                    = var.approved_aims_by_tag
  approved_aims_by_tag_value                              = var.approved_aims_by_tag_value
  aurora_mysql_backtracking_enabled                       = var.aurora_mysql_backtracking_enabled
  aurora_resources_protected_by_backup_plan               = var.aurora_resources_protected_by_backup_plan
  autoscaling_group_elb_healthcheck_required              = var.autoscaling_group_elb_healthcheck_required
  autoscaling_launch_config_public_ip_disabled            = var.autoscaling_launch_config_public_ip_disabled
  backup_plan_min_frequency_and_min_retention_check       = var.backup_plan_min_frequency_and_min_retention_check
  backup_recovery_point_encrypted                         = var.backup_recovery_point_encrypted
  backup_recovery_point_manual_deletion_disabled          = var.backup_recovery_point_manual_deletion_disabled
  backup_recovery_point_minimum_retention_check           = var.backup_recovery_point_minimum_retention_check
  cloudtrail_s3_dataevents_enabled                        = var.cloudtrail_s3_dataevents_enabled
  cloudtrail_security_trail_enabled                       = var.cloudtrail_security_trail_enabled
  cloud_trail_cloud_watch_logs_enabled                    = var.cloud_trail_cloud_watch_logs_enabled
  cloud_trail_enabled                                     = var.cloud_trail_enabled
  cloud_trail_encryption_enabled                          = var.cloud_trail_encryption_enabled
  cloud_trail_log_file_validation_enabled                 = var.cloud_trail_log_file_validation_enabled
  db_instance_backup_enabled                              = var.db_instance_backup_enabled
  desired_instance_tenancy                                = var.desired_instance_tenancy
  desired_instance_tenancy_value                          = var.desired_instance_tenancy_value
  desired_instance_type                                   = var.desired_instance_type
  desired_instance_type_value                             = var.desired_instance_type_value
  ebs_optimized_instance                                  = var.ebs_optimized_instance
  ec2_ebs_encryption_by_default                           = var.ec2_ebs_encryption_by_default
  ec2_instance_detailed_monitoring_enabled                = var.ec2_instance_detailed_monitoring_enabled
  ec2_instance_managed_by_ssm                             = var.ec2_instance_managed_by_ssm
  ec2_instance_profile_attached                           = var.ec2_instance_profile_attached
  ec2_stopped_instance                                    = var.ec2_stopped_instance
  efs_encrypted_check                                     = var.efs_encrypted_check
  eks_endpoint_no_public_access                           = var.eks_endpoint_no_public_access
  eks_secrets_encrypted                                   = var.eks_secrets_encrypted
  elbv2_acm_certificate_required                          = var.elbv2_acm_certificate_required
  elb_acm_certificate_required                            = var.elb_acm_certificate_required
  elb_custom_security_policy_ssl_check                    = var.elb_custom_security_policy_ssl_check
  elb_custom_security_policy_ssl_check_value              = var.elb_custom_security_policy_ssl_check_value
  elb_deletion_protection_enabled                         = var.elb_deletion_protection_enabled
  elb_logging_enabled                                     = var.elb_logging_enabled
  elb_tls_https_listeners_only                            = var.elb_tls_https_listeners_only
  encrypted_volumes                                       = var.encrypted_volumes
  guardduty_non_archived_findings                         = var.guardduty_non_archived_findings
  iam_no_inline_policy_check                              = var.iam_no_inline_policy_check
  iam_policy_blacklisted_check                            = var.iam_policy_blacklisted_check
  iam_policy_blacklisted_check_value                      = var.iam_policy_blacklisted_check_value
  iam_policy_in_use                                       = var.iam_policy_in_use
  iam_policy_in_use_arn                                   = var.iam_policy_in_use_arn
  iam_user_mfa_enabled                                    = var.iam_user_mfa_enabled
  incoming_ssh_disabled                                   = var.incoming_ssh_disabled
  internet_gateway_authorized_vpc_only                    = var.internet_gateway_authorized_vpc_only
  lambda_concurrency_check                                = var.lambda_concurrency_check
  lambda_dlq_check                                        = var.lambda_dlq_check
  lambda_function_public_access_prohibited                = var.lambda_function_public_access_prohibited
  lambda_function_settings_check                          = var.lambda_function_settings_check
  lambda_function_settings_check_value                    = var.lambda_function_settings_check_value
  lambda_inside_vpc                                       = var.lambda_inside_vpc
  mfa_enabled_for_iam_console_access                      = var.mfa_enabled_for_iam_console_access
  no_unrestricted_route_to_igw                            = var.no_unrestricted_route_to_igw
  rds_automatic_minor_version_upgrade_enabled             = var.rds_automatic_minor_version_upgrade_enabled
  rds_cluster_deletion_protection_enabled                 = var.rds_cluster_deletion_protection_enabled
  rds_cluster_iam_authentication_enabled                  = var.rds_cluster_iam_authentication_enabled
  rds_cluster_multi_az_enabled                            = var.rds_cluster_multi_az_enabled
  rds_enhanced_monitoring_enabled                         = var.rds_enhanced_monitoring_enabled
  rds_instance_deletion_protection_enabled                = var.rds_instance_deletion_protection_enabled
  rds_instance_iam_authentication_enabled                 = var.rds_instance_iam_authentication_enabled
  rds_logging_enabled                                     = var.rds_logging_enabled
  rds_multi_az_support                                    = var.rds_multi_az_support
  rds_snapshot_encrypted                                  = var.rds_snapshot_encrypted
  root_account_mfa_enabled                                = var.root_account_mfa_enabled
  s3_bucket_logging_enabled                               = var.s3_bucket_logging_enabled
  s3_bucket_server_side_encryption_enabled                = var.s3_bucket_server_side_encryption_enabled
  s3_bucket_versioning_enabled                            = var.s3_bucket_versioning_enabled
  s3_default_encryption_kms                               = var.s3_default_encryption_kms
  secretsmanager_secret_unused                            = var.secretsmanager_secret_unused
  sns_encrypted_kms                                       = var.sns_encrypted_kms
  vpc_flow_logs_enabled                                   = var.vpc_flow_logs_enabled
  wafv2_logging_enabled                                   = var.wafv2_logging_enabled
  beanstalk_enhanced_health_reporting_enabled             = var.beanstalk_enhanced_health_reporting_enabled
  cloudfront_accesslogs_enabled                           = var.cloudfront_accesslogs_enabled
  cloudfront_associated_with_waf                          = var.cloudfront_associated_with_waf
  cloudfront_custom_ssl_certificate                       = var.cloudfront_custom_ssl_certificate
  cloudfront_default_root_object_configured               = var.cloudfront_default_root_object_configured
  cloudfront_origin_access_identity_enabled               = var.cloudfront_origin_access_identity_enabled
  cloudfront_origin_failover_enabled                      = var.cloudfront_origin_failover_enabled
  cloudfront_sni_enabled                                  = var.cloudfront_sni_enabled
  cloudfront_viewer_policy_https                          = var.cloudfront_viewer_policy_https
  cloudwatch_alarm_action_check                           = var.cloudwatch_alarm_action_check
  cloudwatch_alarm_action_check_value                     = var.cloudwatch_alarm_action_check_value
  cloudwatch_alarm_resource_check                         = var.cloudwatch_alarm_resource_check
  cloudwatch_alarm_resource_check_value                   = var.cloudwatch_alarm_resource_check_value
  cloudwatch_alarm_settings_check                         = var.cloudwatch_alarm_settings_check
  cloudwatch_alarm_settings_check_value                   = var.cloudwatch_alarm_settings_check_value
  cmk_backing_key_rotation_enabled                        = var.cmk_backing_key_rotation_enabled
  codebuild_project_envvar_awscred_check                  = var.codebuild_project_envvar_awscred_check
  codebuild_project_source_repo_url_check                 = var.codebuild_project_source_repo_url_check
  codepipeline_deployment_count_check                     = var.codepipeline_deployment_count_check
  codepipeline_region_fanout_check                        = var.codepipeline_region_fanout_check
  cw_loggroup_retention_period_check                      = var.cw_loggroup_retention_period_check
  dax_encryption_enabled                                  = var.dax_encryption_enabled
  dms_replication_not_public                              = var.dms_replication_not_public
  dynamodb_autoscaling_enabled                            = var.dynamodb_autoscaling_enabled
  dynamodb_in_backup_plan                                 = var.dynamodb_in_backup_plan
  dynamodb_pitr_enabled                                   = var.dynamodb_pitr_enabled
  dynamodb_resources_protected_by_backup_plan             = var.dynamodb_resources_protected_by_backup_plan
  dynamodb_table_encrypted_kms                            = var.dynamodb_table_encrypted_kms
  dynamodb_table_encryption_enabled                       = var.dynamodb_table_encryption_enabled
  dynamodb_throughput_limit_check                         = var.dynamodb_throughput_limit_check
  ebs_in_backup_plan                                      = var.ebs_in_backup_plan
  ebs_resources_protected_by_backup_plan                  = var.ebs_resources_protected_by_backup_plan
  ec2_imdsv2_check                                        = var.ec2_imdsv2_check
  ec2_instance_multiple_eni_check                         = var.ec2_instance_multiple_eni_check
  ec2_instance_no_public_ip                               = var.ec2_instance_no_public_ip
  ec2_managedinstance_applications_blacklisted            = var.ec2_managedinstance_applications_blacklisted
  ec2_managedinstance_applications_blacklisted_value      = var.ec2_managedinstance_applications_blacklisted_value
  ec2_managedinstance_applications_required               = var.ec2_managedinstance_applications_required
  ec2_managedinstance_applications_required_value         = var.ec2_managedinstance_applications_required_value
  ec2_managedinstance_inventory_blacklisted               = var.ec2_managedinstance_inventory_blacklisted
  ec2_managedinstance_association_compliance_status_check = var.ec2_managedinstance_association_compliance_status_check
  ec2_managedinstance_inventory_blacklisted_value         = var.ec2_managedinstance_inventory_blacklisted_value
  ec2_managedinstance_patch_compliance_status_check       = var.ec2_managedinstance_patch_compliance_status_check
  ec2_managedinstance_platform_check                      = var.ec2_managedinstance_platform_check
  ec2_managedinstance_platform_check_value                = var.ec2_managedinstance_platform_check_value
  ec2_resources_protected_by_backup_plan                  = var.ec2_resources_protected_by_backup_plan
  ec2_security_group_attached_to_eni                      = var.ec2_security_group_attached_to_eni
  ecs_task_definition_user_for_host_mode_check            = var.ecs_task_definition_user_for_host_mode_check
  efs_in_backup_plan                                      = var.efs_in_backup_plan
  efs_resources_protected_by_backup_plan                  = var.efs_resources_protected_by_backup_plan
  elasticache_redis_cluster_automatic_backup_check        = var.elasticache_redis_cluster_automatic_backup_check
  elasticsearch_encrypted_at_rest                         = var.elasticsearch_encrypted_at_rest
  elasticsearch_logs_to_cloudwatch                        = var.elasticsearch_logs_to_cloudwatch
  elasticsearch_node_to_node_encryption_check             = var.elasticsearch_node_to_node_encryption_check
  elastic_beanstalk_managed_updates_enabled               = var.elastic_beanstalk_managed_updates_enabled
  elb_cross_zone_load_balancing_enabled                   = var.elb_cross_zone_load_balancing_enabled
  elb_predefined_security_policy_ssl_check                = var.elb_predefined_security_policy_ssl_check
  elb_predefined_security_policy_ssl_check_value          = var.elb_predefined_security_policy_ssl_check_value
  emr_kerberos_enabled                                    = var.emr_kerberos_enabled
  emr_master_no_public_ip                                 = var.emr_master_no_public_ip
  fms_shield_resource_policy_check                        = var.fms_shield_resource_policy_check
  fms_shield_resource_policy_check_value                  = var.fms_shield_resource_policy_check_value
  fms_webacl_resource_policy_check                        = var.fms_webacl_resource_policy_check
  fms_webacl_resource_policy_check_value                  = var.fms_webacl_resource_policy_check_value
  fms_webacl_rulegroup_association_check                  = var.fms_webacl_rulegroup_association_check
  fms_webacl_rulegroup_association_check_value            = var.fms_webacl_rulegroup_association_check_value
  fsx_resources_protected_by_backup_plan                  = var.fsx_resources_protected_by_backup_plan
  iam_customer_policy_blocked_kms_actions                 = var.iam_customer_policy_blocked_kms_actions
  iam_customer_policy_blocked_kms_actions_value           = var.iam_customer_policy_blocked_kms_actions_value
  iam_group_has_users_check                               = var.iam_group_has_users_check
  iam_inline_policy_blocked_kms_actions                   = var.iam_inline_policy_blocked_kms_actions
  iam_inline_policy_blocked_kms_actions_value             = var.iam_inline_policy_blocked_kms_actions_value
  iam_policy_no_statements_with_full_access               = var.iam_policy_no_statements_with_full_access
  iam_role_managed_policy_check                           = var.iam_role_managed_policy_check
  iam_role_managed_policy_check_value                     = var.iam_role_managed_policy_check_value
  iam_user_group_membership_check                         = var.iam_user_group_membership_check
  kms_cmk_not_scheduled_for_deletion                      = var.kms_cmk_not_scheduled_for_deletion
  rds_in_backup_plan                                      = var.rds_in_backup_plan
  rds_resources_protected_by_backup_plan                  = var.rds_resources_protected_by_backup_plan
  redshift_backup_enabled                                 = var.redshift_backup_enabled
  redshift_cluster_configuration_check                    = var.redshift_cluster_configuration_check
  redshift_cluster_configuration_check_value              = var.redshift_cluster_configuration_check_value
  redshift_cluster_kms_enabled                            = var.redshift_cluster_kms_enabled
  redshift_cluster_maintenancesettings_check              = var.redshift_cluster_maintenancesettings_check
  redshift_cluster_maintenancesettings_check_value        = var.redshift_cluster_maintenancesettings_check_value
  redshift_cluster_public_access_check                    = var.redshift_cluster_public_access_check
  redshift_enhanced_vpc_routing_enabled                   = var.redshift_enhanced_vpc_routing_enabled
  redshift_require_tls_ssl                                = var.redshift_require_tls_ssl
  required_tags                                           = var.required_tags
  required_tags_value                                     = var.required_tags_value
  restricted-common-ports                                 = var.restricted-common-ports
  root_account_hardware_mfa_enabled                       = var.root_account_hardware_mfa_enabled
  s3_account_level_public_access_blocks                   = var.s3_account_level_public_access_blocks
  s3_account_level_public_access_blocks_periodic          = var.s3_account_level_public_access_blocks_periodic
  s3_bucket_blacklisted_actions_prohibited                = var.s3_bucket_blacklisted_actions_prohibited
  s3_bucket_blacklisted_actions_prohibited_value          = var.s3_bucket_blacklisted_actions_prohibited_value
  s3_bucket_default_lock_enabled                          = var.s3_bucket_default_lock_enabled
  s3_bucket_level_public_access_prohibited                = var.s3_bucket_level_public_access_prohibited
  s3_bucket_policy_grantee_check                          = var.s3_bucket_policy_grantee_check
  s3_bucket_policy_not_more_permissive                    = var.s3_bucket_policy_not_more_permissive
  s3_bucket_policy_not_more_permissive_value              = var.s3_bucket_policy_not_more_permissive_value
  s3_bucket_public_read_prohibited                        = var.s3_bucket_public_read_prohibited
  s3_bucket_replication_enabled                           = var.s3_bucket_replication_enabled
  sagemaker_endpoint_configuration_kms_key_configured     = var.sagemaker_endpoint_configuration_kms_key_configured
  sagemaker_notebook_instance_kms_key_configured          = var.sagemaker_notebook_instance_kms_key_configured
  sagemaker_notebook_no_direct_internet_access            = var.sagemaker_notebook_no_direct_internet_access
  secretsmanager_rotation_enabled_check                   = var.secretsmanager_rotation_enabled_check
  secretsmanager_scheduled_rotation_success_check         = var.secretsmanager_scheduled_rotation_success_check
  secretsmanager_secret_periodic_rotation                 = var.secretsmanager_secret_periodic_rotation
  secretsmanager_using_cmk                                = var.secretsmanager_using_cmk
  securityhub_enabled                                     = var.securityhub_enabled
  service_vpc_endpoint_enabled                            = var.service_vpc_endpoint_enabled
  service_vpc_endpoint_enabled_value                      = var.service_vpc_endpoint_enabled_value
  shield_advanced_enabled_autorenew                       = var.shield_advanced_enabled_autorenew
  shield_drt_access                                       = var.shield_drt_access
  ssm_document_not_public                                 = var.ssm_document_not_public
  subnet_auto_assign_public_ip_disabled                   = var.subnet_auto_assign_public_ip_disabled
  vpc_network_acl_unused_check                            = var.vpc_network_acl_unused_check
  vpc_sg_open_only_to_authorized_ports                    = var.vpc_sg_open_only_to_authorized_ports
  vpc_vpn_2_tunnels_up                                    = var.vpc_vpn_2_tunnels_up
  waf_classic_logging_enabled                             = var.waf_classic_logging_enabled
  cloudformation_stack_drift_detection_check              = var.cloudformation_stack_drift_detection_check
  cloudformation_stack_drift_detection_check_value        = var.cloudformation_stack_drift_detection_check_value
  cloudformation_stack_notification_check                 = var.cloudformation_stack_notification_check
  elasticsearch_in_vpc_only                               = var.elasticsearch_in_vpc_only
  reliability_pillar                                      = var.reliability_pillar
  security_pillar                                         = var.security_pillar

  variables = {
    SLACK_WEBHOOK = var.slack_webhook
    SLACK_CHANNEL = var.slack_channel
  }
}

#Module      :  GUARD DUTY
module "guardduty" {
  source                         = "./modules/guardduty"
  name                           = "guardduty"
  application                    = var.application
  environment                    = var.environment
  managedby                      = var.managedby
  label_order                    = var.label_order
  enabled                        = var.enabled && var.guardduty_enable
  only_guardduty_enable          = var.only_guardduty_enable
  ipset_location                 = var.ipset_location
  threatintelset_iplist_location = var.threatintelset_iplist_location
  bucket_name                    = var.guardduty_s3_bucket_name
  ipset_format                   = "TXT"
  ipset_iplist                   = var.ipset_iplist
  threatintelset_activate        = var.threatintelset_activate
  threatintelset_format          = "TXT"
  threatintelset_iplist          = var.threatintelset_iplist
  target_bucket                  = var.target_bucket
  target_prefix                  = var.target_prefix
  sse_algorithm                  = var.sse_algorithm
  tracing_mode                   = var.tracing_mode
  attach_tracing_policy          = var.attach_tracing_policy

  is_guardduty_member = var.is_guardduty_member
  member_list         = var.member_list
  variables = {
    minSeverityLevel = "LOW"
    webHookUrl       = var.slack_webhook
    slackChannel     = var.slack_channel
  }
}


## Inspector
module "inspector" {
  source = "./modules/inspector"

  ## Tags
  name        = "inspector"
  application = var.application
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order
  enabled     = var.enabled && var.inspector_enabled

  instance_tags = {
    "Inspector" = true
  }

  duration            = 300
  rules_package_arns  = var.rules_package_arns
  lambda_enabled      = true
  schedule_expression = var.schedule_expression
  handler             = "index.handler"
  runtime             = "nodejs12.x"
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


## Analyzer
module "iam_access_analyzer" {
  source = "./modules/analyzer"

  name        = "analyzer"
  application = var.application
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order
  enabled     = var.enabled && var.analyzer_enable

  ## IAM Access Analyzer
  type = var.type
  variables = {
    SLACK_WEBHOOK = var.slack_webhook
    SLACK_CHANNEL = var.slack_channel
  }
}