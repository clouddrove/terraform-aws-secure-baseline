<!-- This file was automatically generated by the `geine`. Make all changes to `README.yaml` and run `make readme` to rebuild this file. -->

<p align="center"> <img src="https://user-images.githubusercontent.com/50652676/62349836-882fef80-b51e-11e9-99e3-7b974309c7e3.png" width="100" height="100"></p>


<h1 align="center">
    Terraform AWS Secure Baseline
</h1>

<p align="center" style="font-size: 1.2rem;"> 
    Terraform module to create an Secure Basline, inclued module is alarm baseline, config baseline, and clouddtrail baseline.
     </p>

<p align="center">

<a href="https://www.terraform.io">
  <img src="https://img.shields.io/badge/Terraform-v0.15-green" alt="Terraform">
</a>
<a href="LICENSE.md">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="Licence">
</a>


</p>
<p align="center">

<a href='https://facebook.com/sharer/sharer.php?u=https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules/'>
  <img title="Share on Facebook" src="https://user-images.githubusercontent.com/50652676/62817743-4f64cb80-bb59-11e9-90c7-b057252ded50.png" />
</a>
<a href='https://www.linkedin.com/shareArticle?mini=true&title=Terraform+AWS+Secure+Baseline&url=https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules/'>
  <img title="Share on LinkedIn" src="https://user-images.githubusercontent.com/50652676/62817742-4e339e80-bb59-11e9-87b9-a1f68cae1049.png" />
</a>
<a href='https://twitter.com/intent/tweet/?text=Terraform+AWS+Secure+Baseline&url=https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules/'>
  <img title="Share on Twitter" src="https://user-images.githubusercontent.com/50652676/62817740-4c69db00-bb59-11e9-8a79-3580fbbf6d5c.png" />
</a>

</p>
<hr>


We eat, drink, sleep and most importantly love **DevOps**. We are working towards strategies for standardizing architecture while ensuring security for the infrastructure. We are strong believer of the philosophy <b>Bigger problems are always solved by breaking them into smaller manageable problems</b>. Resonating with microservices architecture, it is considered best-practice to run database, cluster, storage in smaller <b>connected yet manageable pieces</b> within the infrastructure. 

This module is basically combination of [Terraform open source](https://www.terraform.io/) and includes automatation tests and examples. It also helps to create and improve your infrastructure with minimalistic code instead of maintaining the whole infrastructure code yourself.

We have [*fifty plus terraform modules*][terraform_modules]. A few of them are comepleted and are available for open source usage while a few others are in progress.




## Prerequisites

This module has a few dependencies: 

- [Terraform 0.13](https://learn.hashicorp.com/terraform/getting-started/install.html)
- [Go](https://golang.org/doc/install)
- [github.com/stretchr/testify/assert](https://github.com/stretchr/testify)
- [github.com/gruntwork-io/terratest/modules/terraform](https://github.com/gruntwork-io/terratest)







## Examples


**IMPORTANT:** Since the `master` branch used in `source` varies based on new modifications, we suggest that you use the release versions [here](https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules//releases).


### Simple Example
Here is an example of how you can use this module in your inventory structure:
```hcl
module "secure_baseline" {
  source        = "clouddrove/secure-baseline/aws"
  environment = "test"
  label_order = ["environment", "name"]

  enabled       = true
  slack_webhook = "https://hooks.slack.com/services/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uEG4TW"
  slack_channel = "testing"

  # cloudtrail
  cloudtrail_enabled                = true
  key_deletion_window_in_days       = 10
  cloudwatch_logs_retention_in_days = 365
  cloudwatch_logs_group_name        = "cloudtrail-log-group"
  cloudtrail_bucket_name            = "cloudtrail-bucket-logs"


  # Alarm
  alarm_enabled            = true
  alarm_namespace          = "Alert_Alarm"
  unauthorized_api_calls   = true
  no_mfa_console_signin    = true
  root_usage               = true
  iam_changes              = true
  cloudtrail_cfg_changes   = true
  console_signin_failures  = true
  disable_or_delete_cmk    = true
  s3_bucket_policy_changes = true
  security_group_changes   = true
  nacl_changes             = true
  network_gw_changes       = true
  route_table_changes      = true
  vpc_changes              = true


  ## Config
  config_enabled                     = true
  config_s3_bucket_name              = "config-bucket"
  restricted_ports                   = true
  iam_mfa                            = true
  unused_credentials                 = true
  user_no_policies                   = true
  no_policies_with_full_admin_access = true
  acm_certificate_expiration_check   = true
  ec2_volume_inuse_check             = true
  ebs_snapshot_public_restorable     = true
  rds_instance_public_access_check   = true
  rds_snapshots_public_prohibited    = true
  guardduty_enabled_centralized      = true
  s3_bucket_public_write_prohibited  = true
  eip_attached                       = false
  ec2_encrypted_volumes              = true
  iam_root_access_key                = true
  vpc_default_security_group_closed  = false
  s3_bucket_ssl_requests_only        = false
  multi_region_cloudtrail_enabled    = true
  instances_in_vpc                   = true
  cloudwatch_log_group_encrypted     = false
  rds_storage_encrypted              = true
  restricted_ports_list              = "{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"

  # guardduty
  guardduty_enable         = true
  guardduty_s3_bucket_name = "guardduty-files"
  ipset_iplist             = ["10.10.0.0/16", "172.16.0.0/16", ]
  threatintelset_activate  = false
  threatintelset_iplist    = ["192.168.2.0/32", "4.4.4.4", ]

  ## Inspector
  rules_package_arns = [
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-ubA5XvBh",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-sJBhCr0F",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SPzU33xe",
    "arn:aws:inspector:eu-west-1:357557129151:rulespackage/0-SnojL3Z6",
  ]
}
```






## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| EVENT\_ALERT\_LIST | Event List which event is not ignore. | `string` | `""` | no |
| EVENT\_IGNORE\_LIST | Event List which event is ignore. | `string` | `""` | no |
| SOURCE\_LIST | Event Source List which event is ignore. | `string` | `""` | no |
| USER\_IGNORE\_LIST | User List which event is ignore. | `string` | `""` | no |
| acm\_certificate\_expiration\_check | Check ACM Certificates in your account are marked for expiration within the specified number of days. | `bool` | `false` | no |
| acm\_days\_to\_expiration | Specify the number of days before the rule flags the ACM Certificate as noncompliant. | `number` | `14` | no |
| alarm\_enabled | The boolean flag whether alarm module is enabled or not. No resources are created when set to false. | `bool` | `true` | no |
| alarm\_namespace | The namespace in which all alarms are set up. | `string` | `"CISBenchmark"` | no |
| analyzer\_enable | The boolean flag whether alarm module is enabled or not. No resources are created when set to false. | `bool` | `true` | no |
| attributes | Additional attributes (e.g. `1`). | `list(any)` | `[]` | no |
| cloudtrail\_bucket\_name | The name of the S3 bucket which will store configuration snapshots. | `string` | n/a | yes |
| cloudtrail\_cfg\_changes | If you want to create alarm when any changes in cloudtrail cfg. | `bool` | `true` | no |
| cloudtrail\_enabled | The boolean flag whether cloudtrail module is enabled or not. No resources are created when set to false. | `bool` | `true` | no |
| cloudtrail\_s3\_policy | Policy for S3. | `string` | `""` | no |
| cloudwatch\_log\_group\_encrypted | Ensuring that log group is encrypted | `bool` | `false` | no |
| cloudwatch\_logs\_group\_name | The name of CloudWatch Logs group to which CloudTrail events are delivered. | `string` | `"iam_role_name"` | no |
| cloudwatch\_logs\_retention\_in\_days | Number of days to retain logs for. CIS recommends 365 days.  Possible values are: 0, 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, and 3653. Set to 0 to keep logs indefinitely. | `number` | `365` | no |
| config\_cloudtrail\_enabled | Ensuring that the cloudtrail is enabled. | `bool` | `false` | no |
| config\_enabled | The boolean flag whether config module is enabled or not. No resources are created when set to false. | `bool` | `true` | no |
| config\_s3\_bucket\_name | The name of the S3 bucket which will store logs for aws  config. | `string` | n/a | yes |
| console\_signin\_failures | If you want to create alarm when any changes in cloudtrail cfg. | `bool` | `true` | no |
| delimiter | Delimiter to be used between `organization`, `environment`, `name` and `attributes`. | `string` | `"-"` | no |
| disable\_or\_delete\_cmk | If you want to create alarm when disable or delete in cmk. | `bool` | `true` | no |
| ebs\_snapshot\_public\_restorable | Checks whether Amazon Elastic Block Store snapshots are not publicly restorable. | `bool` | `false` | no |
| ec2\_encrypted\_volumes | Evaluates whether EBS volumes that are in an attached state are encrypted. Optionally, you can specify the ID of a KMS key to use to encrypt the volume. | `bool` | `false` | no |
| ec2\_volume\_inuse\_check | Checks whether EBS volumes are attached to EC2 instances. | `bool` | `false` | no |
| eip\_attached | Checks whether all Elastic IP addresses that are allocated to a VPC are attached to EC2 instances or in-use elastic network interfaces (ENIs). | `bool` | `false` | no |
| enabled | The boolean flag whether this module is enabled or not. No resources are created when set to false. | `bool` | `true` | no |
| environment | Environment (e.g. `prod`, `dev`, `staging`). | `string` | `""` | no |
| event\_selector | Specifies an event selector for enabling data event logging. See: https://www.terraform.io/docs/providers/aws/r/cloudtrail.html for details on this variable | <pre>list(object({<br>    include_management_events = bool<br>    read_write_type           = string<br><br>  }))</pre> | `[]` | no |
| guardduty\_enable | Enable monitoring and feedback reporting. Setting to false is equivalent to `suspending` GuardDuty. Defaults to true | `bool` | `true` | no |
| guardduty\_enabled\_centralized | Checks whether Amazon GuardDuty is enabled in your AWS account and region. | `bool` | `false` | no |
| guardduty\_s3\_bucket\_name | The name of the S3 bucket which will store guardduty files. | `string` | n/a | yes |
| iam\_changes | If you want to create alarm when any changes in IAM. | `bool` | `true` | no |
| iam\_mfa | Check MFA is enabled. | `bool` | `false` | no |
| iam\_password\_policy | Ensuring that log group is encrypted | `bool` | `false` | no |
| iam\_root\_access\_key | Checks whether the root user access key is available. The rule is COMPLIANT if the user access key does not exist. | `bool` | `false` | no |
| inspector\_enabled | Whether Inspector is enabled or not. | `bool` | `true` | no |
| instances\_in\_vpc | Ensuring that all the instances in VPC | `bool` | `false` | no |
| ipset\_iplist | IPSet list of trusted IP addresses | `list(any)` | `[]` | no |
| is\_guardduty\_member | Whether the account is a member account | `bool` | `false` | no |
| key\_deletion\_window\_in\_days | Duration in days after which the key is deleted after destruction of the resource, must be between 7 and 30 days. Defaults to 30 days. | `number` | `10` | no |
| label\_order | Label order, e.g. `name`,`application`. | `list(any)` | `[]` | no |
| managedby | ManagedBy, eg 'CloudDrove' | `string` | `"hello@clouddrove.com"` | no |
| member\_list | The list of member accounts to be added. Each member list need to have values of account\_id, member\_email and invite boolean | <pre>list(object({<br>    account_id = string<br>    email      = string<br>    invite     = bool<br>  }))</pre> | `[]` | no |
| multi\_region\_cloudtrail\_enabled | Ensuring that the multi-region-cloud-trail is enabled | `bool` | `false` | no |
| nacl\_changes | If you want to create alarm when any changes in nacl. | `bool` | `true` | no |
| name | Name  (e.g. `app` or `cluster`). | `string` | `""` | no |
| network\_gw\_changes | If you want to create alarm when any changes in network gateway. | `bool` | `true` | no |
| no\_mfa\_console\_signin | If you want to create alarm when MFA not enabled on root user. | `bool` | `true` | no |
| no\_policies\_with\_full\_admin\_access | Check user no policies with full admin access. | `bool` | `false` | no |
| password\_max\_age | Number of days before password expiration. | `number` | `90` | no |
| password\_min\_length | Password minimum length. | `number` | `16` | no |
| password\_require\_lowercase | Require at least one lowercase character in password. | `bool` | `true` | no |
| password\_require\_numbers | Require at least one number in password. | `bool` | `true` | no |
| password\_require\_symbols | Require at least one symbol in password. | `bool` | `true` | no |
| password\_require\_uppercase | Require at least one uppercase character in password. | `bool` | `true` | no |
| password\_reuse\_prevention | Number of passwords before allowing reuse. | `number` | `24` | no |
| rds\_instance\_public\_access\_check | Checks whether the Amazon Relational Database Service (RDS) instances are not publicly accessible. | `bool` | `false` | no |
| rds\_snapshots\_public\_prohibited | Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. | `bool` | `false` | no |
| rds\_storage\_encrypted | Checks whether storage encryption is enabled for your RDS DB instances. | `bool` | `false` | no |
| restricted\_ports | If you want to enable the restricted incoming port. | `bool` | `false` | no |
| restricted\_ports\_list | This list of blocked ports. | `string` | `"{\"blockedPort1\": \"22\", \"blockedPort2\": \"3306\",\"blockedPort3\": \"6379\", \"blockedPort4\": \"5432\"}"` | no |
| root\_usage | If you want to create alarm when sign in with root user. | `bool` | `true` | no |
| route\_table\_changes | If you want to create alarm when any changes in network gateway. | `bool` | `true` | no |
| rules\_package\_arns | The rules to be used during the run. | `list(string)` | `[]` | no |
| s3\_bucket\_policy\_changes | If you want to create alarm when any changes in S3 policy. | `bool` | `true` | no |
| s3\_bucket\_public\_write\_prohibited | Checks that your S3 buckets do not allow public write access. | `bool` | `false` | no |
| s3\_bucket\_ssl\_requests\_only | Checks whether S3 buckets have policies that require requests to use Secure Socket Layer (SSL). | `bool` | `false` | no |
| schedule\_expression | AWS Schedule Expression: https://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html | `string` | `"cron(0 14 ? * THU *)"` | no |
| security\_group\_changes | If you want to create alarm when any changes on security groups. | `bool` | `true` | no |
| slack\_channel | The channel of slack. | `string` | n/a | yes |
| slack\_webhook | The webhook of slack. | `string` | n/a | yes |
| sns\_topic\_name | Specifies the name of the Amazon SNS topic defined for notification of log file delivery | `string` | `null` | no |
| tags | Additional tags (e.g. map(`BusinessUnit`,`XYZ`). | `map(any)` | `{}` | no |
| threatintelset\_activate | Specifies whether GuardDuty is to start using the uploaded ThreatIntelSet | `bool` | `true` | no |
| threatintelset\_iplist | ThreatIntelSet list of known malicious IP addresses | `list(any)` | `[]` | no |
| type | Type of Analyzer. Valid value is currently only ACCOUNT. Defaults to ACCOUNT. | `string` | `"ACCOUNT"` | no |
| unauthorized\_api\_calls | If you want to create alarm for unauthorized api calls. | `bool` | `true` | no |
| unused\_credentials | Check unused credentials in AWS account. | `bool` | `false` | no |
| user\_no\_policies | Check user no policies. | `bool` | `false` | no |
| vpc\_changes | If you want to create alarm when any changes in vpc. | `bool` | `true` | no |
| vpc\_default\_security\_group\_closed | Checks that the default security group of any Amazon Virtual Private Cloud (VPC) does not allow inbound or outbound traffic. | `bool` | `false` | no |

## Outputs

| Name | Description |
|------|-------------|
| cloudtrail\_arn | The Amazon Resource Name of the trail |
| tags | A mapping of tags to assign to the Cloudtrail. |




## Testing
In this module testing is performed with [terratest](https://github.com/gruntwork-io/terratest) and it creates a small piece of infrastructure, matches the output like ARN, ID and Tags name etc and destroy infrastructure in your AWS account. This testing is written in GO, so you need a [GO environment](https://golang.org/doc/install) in your system. 

You need to run the following command in the testing folder:
```hcl
  go test -run Test
```



## Feedback 
If you come accross a bug or have any feedback, please log it in our [issue tracker](https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules//issues), or feel free to drop us an email at [hello@clouddrove.com](mailto:hello@clouddrove.com).

If you have found it worth your time, go ahead and give us a ★ on [our GitHub](https://github.com/clouddrove/clouddrove/terraform-aws-secure-baseline/modules/)!

## About us

At [CloudDrove][website], we offer expert guidance, implementation support and services to help organisations accelerate their journey to the cloud. Our services include docker and container orchestration, cloud migration and adoption, infrastructure automation, application modernisation and remediation, and performance engineering.

<p align="center">We are <b> The Cloud Experts!</b></p>
<hr />
<p align="center">We ❤️  <a href="https://github.com/clouddrove">Open Source</a> and you can check out <a href="https://github.com/clouddrove">our other modules</a> to get help with your new Cloud ideas.</p>

  [website]: https://clouddrove.com
  [github]: https://github.com/clouddrove
  [linkedin]: https://cpco.io/linkedin
  [twitter]: https://twitter.com/clouddrove/
  [email]: https://clouddrove.com/contact-us.html
  [terraform_modules]: https://github.com/clouddrove?utf8=%E2%9C%93&q=terraform-&type=&language=
