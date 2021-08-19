data "aws_iam_policy_document" "ecs_instance_compensate" {            
              statement {            
                actions   = ["ec2:DescribeInstances"]            
                resources = ["*"]            
              }            
              statement {            
                actions   = ["ecs:StartTask"]            
                resources = ["*"]            
              }            
              statement {            
                actions   = ["logs:*"]            
                resources = ["arn:aws:logs:*:*:*"]            
              }            
            }            
            
            resource "aws_iam_policy" "ecs_instance_compensate" {            
              count = var.dtap_short_name == "prod" ? 1 : 0            
            
              name        = "simacan-services-${var.dtap_short_name}-ECSInstancePolicyCompensateForLostPolicies${var.cloudformation_appendices["iam_policy_compensate"]}"            
              policy      = data.aws_iam_policy_document.ecs_instance_compensate.json            
              description = "IAM policy temporarily granting rights available before through an inline policy"            
            }            
            
            data "aws_iam_policy_document" "ecs_instance_deny" {            
              statement {            
                effect    = "Deny"            
                actions   = ["ecs:CreateCluster"]            
                resources = ["*"]            
              }            
            }            
            
            resource "aws_iam_policy" "ecs_instance_deny" {            
              name        = "simacan-services-${var.dtap_short_name}-ECSInstancePolicyDenyECSCreateCluster${var.cloudformation_appendices["iam_policy_deny"]}"            
              policy      = data.aws_iam_policy_document.ecs_instance_deny.json            
              description = "IAM policy denying the ECS action CreateCluster"            
            }            
            
            resource "aws_iam_role" "services" {            
              name = "simacan-services-${var.dtap_short_name}-ECSInstanceRole${var.cloudformation_appendices["iam_role"]}"            
            
              assume_role_policy = jsonencode({            
                Version = "2012-10-17"            
                Statement = [            
                  {            
                    Effect = "Allow"            
                    Action = "sts:AssumeRole"            
                    Principal = {            
                      Service = "ec2.amazonaws.com"            
                    }            
                  }            
                ]            
              })            
            
              managed_policy_arns = var.dtap_short_name == "prod" ? [            
                aws_iam_policy.ecs_instance_compensate[0].arn,            
                aws_iam_policy.ecs_instance_deny.arn,            
                "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",            
                "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",            
                "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"            
                ] : [            
                aws_iam_policy.ecs_instance_deny.arn,            
                "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess",            
                "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",            
                "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"            
              ]            
            
              inline_policy {}            
            
              tags = {            
                "DTAP Environment" = var.dtap_alias            
              }            
            }            
            
            resource "aws_iam_instance_profile" "services" {            
              name = "simacan-services-${var.dtap_short_name}-ECSInstanceProfile${var.cloudformation_appendices["iam_instance_profile"]}"            
              role = aws_iam_role.services.name            
            }
