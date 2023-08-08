data "aws_partition" "security_hub" {}
data "aws_region" "security_hub" {}

locals {
  enabled_standards_arns = var.security_hub_enabled ? toset([
    for standard in var.enabled_standards :
    format("arn:%s:securityhub:%s::%s", data.aws_partition.security_hub.partition, length(regexall("ruleset", standard)) == 0 ? data.aws_region.security_hub.name : "", standard)
  ]) : []

  enabled_products_arns = var.security_hub_enabled ? toset([
    for product in var.enabled_products :
    format("arn:%s:securityhub:%s::%s", data.aws_partition.security_hub.partition, length(regexall("ruleset", product)) == 0 ? data.aws_region.security_hub.name : "", product)
  ]) : []
}

resource "aws_securityhub_account" "security_hub" {
  count                     = var.security_hub_enabled ? 1 : 0
  enable_default_standards  = var.enable_default_standards
  control_finding_generator = var.control_finding_generator
  auto_enable_controls      = var.auto_enable_controls
}

resource "aws_securityhub_standards_subscription" "standards" {
  for_each      = local.enabled_standards_arns
  depends_on    = [aws_securityhub_account.security_hub]
  standards_arn = each.key
}

resource "aws_securityhub_product_subscription" "products" {
  for_each    = local.enabled_products_arns
  depends_on  = [aws_securityhub_account.security_hub]
  product_arn = each.key
}

# To enable add member account to security-hub. 
resource "aws_securityhub_member" "example" {
  for_each   = { for member in var.member_details : member.account_id => member }
  account_id = each.value.account_id
  email      = each.value.mail_id
  invite     = each.value.invite

  depends_on = [
    aws_securityhub_account.security_hub
  ]
}

# To inivitation from another security-hub account to current account.
resource "aws_securityhub_invite_accepter" "invitee" {
  count      =  var.security_hub_enabled && var.master_account_id == "" ? 0 : 1
  master_id  = var.master_account_id # Master id of the root security hub account. e.g. aws_securityhub_account.security_hub[0].master_id

  depends_on = [ 
    aws_securityhub_account.security_hub 
  ]
}
