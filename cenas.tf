resource "aws_iam_group" "simacan_developers" {
  # Although external employees get the same privileges
  # it's administratively useful to keep a boundary.
  for_each = toset(["Developers", "BusyMachines"])

  name = each.key
}

locals {
  # Slightly cumbersome way of saying it's all the groups above again,
  # but this ensures that depended resources are deployed after group creation.
  referenced_group_name_set = toset([for group in aws_iam_group.simacan_developers : group.name])
}

resource "aws_iam_group_policy_attachment" "developer_view_only_group_policy" {
  for_each = local.referenced_group_name_set

  group = each.key
  # Generally shows all resource/service configurations, but no data.
  policy_arn = "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
}

resource "aws_iam_group_policy_attachment" "developer_change_password" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = "arn:aws:iam::aws:policy/IAMUserChangePassword"
}

data "aws_iam_policy_document" "simacan_manage_access" {
  statement {
    actions = [
      "iam:UpdateAccessKey",
      "iam:DeleteAccessKey",
      "iam:CreateAccessKey",
      "iam:UpdateLoginProfile",
      "iam:DeleteLoginProfile",
      "iam:CreateLoginProfile"
    ]
    # Slightly weird way of escaping used here:
    # https://www.terraform.io/docs/language/expressions/strings.html
    resources = ["arn:aws:iam::*:user/$${aws:username}"]
  }
  statement {
    actions   = ["sts:DecodeAuthorizationMessage"]
    resources = ["*"]
  }
  statement {
    actions = [
      "ec2:AuthorizeSecurityGroupEgress",
      "ec2:AuthorizeSecurityGroupIngress",
      "ec2:RevokeSecurityGroupEgress",
      "ec2:RevokeSecurityGroupIngress",
      "ec2:ModifySecurityGroupRules",
      "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
      "ec2:UpdateSecurityGroupRuleDescriptionsIngress"
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "ec2:ResourceTag/Name"
      values   = ["OpenVPN whitelist"]
    }
  }
}

resource "aws_iam_policy" "simacan_manage_access" {
  name   = "developer-manage-access"
  policy = data.aws_iam_policy_document.simacan_manage_access.json
}

resource "aws_iam_group_policy_attachment" "simacan_manage_access" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_manage_access.arn
}

# Additional resources/services to which developers need read all access.
# A lot of these privilege sets are covered by some AWS-managed ReadOnlyAccess policies,
# but you can only attach up to 10 policies to a single IAM entity.
data "aws_iam_policy_document" "simacan_developer_read_all" {
  statement {
    sid = "automation"
    actions = [
      "cloudformation:Describe*",
      "cloudformation:EstimateTemplateCost",
      "cloudformation:Get*",
      "cloudformation:ValidateTemplate",
      "cloudformation:Detect*",
      "codepipeline:Get*",
      "codepipeline:List*",
      "serverlessrepo:Get*",
      "serverlessrepo:List*",
      "serverlessrepo:Search*"
    ]
    resources = ["*"]
  }
  statement {
    sid = "aws"
    actions = [
      "aws-portal:ViewBilling", # This can also be seen through metrics and logs.
      "route53domains:ViewBilling",
      "support:Describe*",
      "support:SearchForCases"
    ]
    resources = ["*"]
  }
  statement {
    sid = "compute"
    actions = [
      "application-autoscaling:Describe*",
      "batch:Describe*",
      "batch:List*",
      "ec2:Describe*",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability",
      "ecr:Describe*",
      "ecr:Get*",
      "ecr:List*",
      "elasticloadbalancing:Describe*",
      "lambda:Get*"
    ]
    resources = ["*"]
  }
  statement {
    sid = "data"
    actions = [
      "athena:*",
      "dynamodb:BatchGetItem",
      "dynamodb:Describe*",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "glue:List*",
      "glue:Get*",
      "rds:Copy*",
      "rds:CreateDBSnapshot",
      "rds:DownloadCompleteDBLogFile",
      "rds:DownloadDBLogFilePortion",
      "rds:ListTagsForResource",
      "s3:Get*",
      "s3:List*"
    ]
    # In the future this should be curbed to dev only.
    resources = ["*"]
  }
  statement {
    sid = "messaging"
    actions = [
      "events:DescribeRule",
      "events:TestEventPattern",
      "events:DescribeEventBus",
      "sns:GetTopicAttributes",
      "sqs:Get*",
      "sqs:ListDeadLetterSourceQueues"
    ]
    resources = ["*"]
  }
  statement {
    sid = "monitoring"
    actions = [
      "cloudtrail:Get*",
      "cloudtrail:List*",
      "cloudwatch:Describe*",
      "config:Get*",
      "config:Select*",
      "health:Describe*",
      "pi:*",
      "logs:Describe*",
      "logs:Get*",
      "logs:List*",
      "logs:StartQuery",
      "logs:StopQuery",
      "logs:TestMetricFilter",
      "logs:FilterLogEvents"
    ]
    resources = ["*"]
  }
  statement {
    sid = "networking"
    actions = [
      "acm:DescribeCertificate",
      "acm:GetCertificate",
      "apigateway:GET",
      "cloudfront:Get*",
      "route53:TestDNSAnswer",
      "route53domains:CheckDomainAvailability",
      "route53domains:Get*",
      "route53domains:RetrieveDomainAuthCode",
      "wafv2:Get*",
      "wafv2:Describe*",
      "wafv2:CheckCapacity"
    ]
    resources = ["*"]
  }
  statement {
    sid = "security"
    actions = [
      "iam:GenerateCredentialReport",
      "iam:GenerateServiceLastAccessedDetails",
      "iam:Get*",
      "iam:SimulateCustomPolicy",
      "iam:SimulatePrincipalPolicy",
      "kms:Describe*",
      "kms:Get*",
      "kms:List*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "simacan_developer_read_all" {
  name   = "developer-read-only"
  policy = data.aws_iam_policy_document.simacan_developer_read_all.json
}

resource "aws_iam_group_policy_attachment" "simacan_developer_read_all" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_developer_read_all.arn
}

# All dev/stg write privileges developers have are too much for one IAM policy document...
data "aws_iam_policy_document" "simacan_write_dev_stg_other" {
  statement {
    actions = ["cloudwatch:*"]
    resources = concat(
      formatlist("arn:aws:cloudwatch:${data.aws_region.current.name}:*:alarm:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:cloudwatch::*:dashboard/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:cloudwatch:${data.aws_region.current.name}:*:insight-rule/%s", local.non_prod_naming_patterns)
    )
  }
  statement {
    actions = ["events:*"]
    resources = concat(
      formatlist("arn:aws:events:${data.aws_region.current.name}:*:archive/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:events:${data.aws_region.current.name}:*:event-bus/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:events:${data.aws_region.current.name}::event-source/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:events:${data.aws_region.current.name}:*:replay/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:events:${data.aws_region.current.name}:*:rule/%s/*", local.non_prod_naming_patterns)
    )
  }
  statement {
    actions = ["logs:*"]
    resources = concat(
      formatlist("arn:aws:logs:${data.aws_region.current.name}:*:log-group:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:logs:${data.aws_region.current.name}:*:log-group:%s:log-stream:*", local.non_prod_naming_patterns)
    )
  }
}

resource "aws_iam_policy" "simacan_write_dev_stg_other" {
  name   = "developer-write-dev-stg-other"
  policy = data.aws_iam_policy_document.simacan_write_dev_stg_other.json
}

resource "aws_iam_group_policy_attachment" "simacan_write_dev_stg_other" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_write_dev_stg_other.arn
}

locals {
  # it's not so easy to replace a whole ALB to conform to naming conventions
  non_prod_elb_patterns = [for pattern in local.non_prod_naming_patterns : replace(pattern, "stg", "staging")]
}

data "aws_iam_policy_document" "simacan_write_dev_stg_compute" {
  # the recourse naming restrictions are little more lenient here, because the autoscaling groups followed a different naming convention
  statement {
    actions = ["autoscaling:*"]
    resources = concat(
      formatlist("arn:aws:autoscaling:${data.aws_region.current.name}:*:launchConfiguration:*:launchConfigurationName/%s*", local.non_prod_naming_patterns),
      formatlist("arn:aws:autoscaling:${data.aws_region.current.name}:*:autoScalingGroup:*:autoScalingGroupName/%s*", local.non_prod_naming_patterns)
    )
  }
  # the recourse naming restrictions are little more lenient here, because the load balancers followed a different naming convention
  statement {
    actions = ["elasticloadbalancing:*"]
    resources = concat(
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:loadbalancer/net/%s*/*", local.non_prod_elb_patterns),
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:loadbalancer/app/%s*/*", local.non_prod_elb_patterns),
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:listener/net/%s*/*/*", local.non_prod_elb_patterns),
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:listener-rule/net/%s*/*/*/*", local.non_prod_elb_patterns),
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:listener/app/%s*/*/*", local.non_prod_elb_patterns),
      formatlist("arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:listener-rule/app/%s*/*/*/*", local.non_prod_elb_patterns),
      [
        "arn:aws:elasticloadbalancing:${data.aws_region.current.name}:*:targetgroup/*/*"
      ]
    )
  }
  statement {
    actions = ["lambda:*"]
    resources = concat(
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:codesigningconfig:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:event-source-mapping:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:function:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:function:%s:*", local.non_prod_naming_patterns),
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:layer:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:lambda:${data.aws_region.current.name}:*:layer:%s:*", local.non_prod_naming_patterns)
    )
  }
}

resource "aws_iam_policy" "simacan_write_dev_stg_compute" {
  name   = "developer-write-dev-stg-compute"
  policy = data.aws_iam_policy_document.simacan_write_dev_stg_compute.json
}

resource "aws_iam_group_policy_attachment" "simacan_write_dev_stg_compute" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_write_dev_stg_compute.arn
}

data "aws_iam_policy_document" "simacan_write_dev_stg_dbs" {
  statement {
    actions = ["dynamodb:*"]
    resources = concat(
      formatlist("arn:aws:dynamodb:${data.aws_region.current.name}:*:table/%s/backup/*", local.non_prod_naming_patterns),
      formatlist("arn:aws:dynamodb:${data.aws_region.current.name}:*:table/%s/export/*", local.non_prod_naming_patterns),
      formatlist("arn:aws:dynamodb::*:global-table/%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:dynamodb:${data.aws_region.current.name}:*:table/%s/index/*", local.non_prod_naming_patterns),
      formatlist("arn:aws:dynamodb:${data.aws_region.current.name}:*:table/%s/stream/*", local.non_prod_naming_patterns),
      formatlist("arn:aws:dynamodb:${data.aws_region.current.name}:*:table/%s", local.non_prod_naming_patterns)
    )
  }
  statement {
    actions   = ["elasticache:RebootCacheCluster"]
    resources = formatlist("arn:aws:elasticache:${data.aws_region.current.name}:*:cluster:%s", local.non_prod_naming_patterns)
  }
  statement {
    actions = [
      "rds:ApplyPendingMaintenanceAction",
      "rds:CreateDBParameterGroup",
      "rds:DeleteDBParameterGroup",
      "rds:FailoverDBCluster",
      "rds:AddTagsToResource",
      "rds:Modify*",
      "rds:RebootDBInstance",
      "rds:RemoveTagsFromResource",
      "rds:ResetDBParameterGroup"
    ]
    resources = concat(
      formatlist("arn:aws:rds:${data.aws_region.current.name}:*:db:%s", local.non_prod_naming_patterns),
      formatlist("arn:aws:rds:${data.aws_region.current.name}:*:snapshot:%s", local.non_prod_naming_patterns),
      # AWS prepends rds: and appends a datetime to names of automated backups
      formatlist("arn:aws:rds:${data.aws_region.current.name}:*:snapshot:rds:%s-????-??-??-??-??", local.non_prod_naming_patterns),
      [
        "arn:aws:rds:${data.aws_region.current.name}:*:og:*:*",
        "arn:aws:rds:${data.aws_region.current.name}:*:pg:*",
        "arn:aws:rds:${data.aws_region.current.name}:*:subgrp:*"
      ]
    )
  }
}

resource "aws_iam_policy" "simacan_write_dev_stg_dbs" {
  name   = "developer-write-dev-stg-dbs"
  policy = data.aws_iam_policy_document.simacan_write_dev_stg_dbs.json
}

resource "aws_iam_group_policy_attachment" "simacan_write_dev_stg_dbs" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_write_dev_stg_dbs.arn
}

# Full access privileges should be curbed in the future,
# particularly S3 and IAM PassRole.
data "aws_iam_policy_document" "simacan_write_all" {
  statement {
    actions = [
      "batch:DeregisterJobDefinition",
      "batch:TerminateJob",
      "batch:CancelJob",
      "batch:SubmitJob",
      "batch:RegisterJobDefinition",
      "cloudfront:CreateInvalidation",
      "cloudfront:UpdateDistribution",
      "cloudfront:UpdateStreamingDistribution",
      "cloudfront:UpdateCloudFrontOriginAccessIdentity",
      "ecr:*",
      "ecs:CreateService",
      "ecs:DeleteService",
      "ecs:Poll",
      "ecs:RegisterTaskDefinition",
      "ecs:RunTask",
      "ecs:StartTask",
      "ecs:StopTask",
      "ecs:SubmitContainerStateChange",
      "ecs:SubmitTaskStateChange",
      "ecs:UpdateContainerAgent",
      "ecs:UpdateService",
      "ecs:DeregisterContainerInstance",
      "ecs:DiscoverPollEndpoint",
      "ecs:RegisterContainerInstance",
      "ecs:StartTelemetrySession",
      "ecs:Submit*",
      "ecs:DeregisterTaskDefinition",
      "ecs:UpdateContainerInstancesState",
      "iam:PassRole",
      "route53:ChangeResourceRecordSets",
      "route53:ChangeTagsForResource",
      "route53:CreateTrafficPolicy",
      "route53:CreateTrafficPolicyInstance",
      "route53:CreateTrafficPolicyVersion",
      "route53:DeleteTrafficPolicy",
      "route53:DeleteTrafficPolicyInstance",
      "route53:DisableDomainAutoRenew",
      "route53:EnableDomainAutoRenew",
      "route53:UpdateHealthCheck",
      "route53:UpdateHostedZoneComment",
      "route53:UpdateTrafficPolicyComment",
      "route53:UpdateTrafficPolicyInstance",
      "route53domains:DisableDomainAutoRenew",
      "route53domains:EnableDomainAutoRenew",
      "route53domains:RenewDomain",
      "route53domains:ResendContactReachabilityEmail",
      "route53domains:UpdateDomainContact",
      "route53domains:UpdateDomainContactPrivacy",
      "route53domains:UpdateDomainNameservers",
      "route53domains:UpdateTagsForDomain",
      "s3:*",
      "support:*"
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "simacan_write_all" {
  name   = "developer-write-all"
  policy = data.aws_iam_policy_document.simacan_write_all.json
}

resource "aws_iam_group_policy_attachment" "simacan_write_all" {
  for_each = local.referenced_group_name_set

  group      = each.key
  policy_arn = aws_iam_policy.simacan_write_all.arn
}
