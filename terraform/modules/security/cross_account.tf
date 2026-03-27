# Enterprise SOAR Multi-Account Security Module
# Enables SOAR to respond to incidents across multiple AWS accounts

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ==========================================
# Cross-Account Role for SOAR Response
# ==========================================
resource "aws_iam_role" "cross_account_responder" {
  name = "${var.environment}-soar-cross-account-responder"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSOARAccountAssumeRole"
        Effect = "Allow"
        Action = "sts:AssumeRole"
        Principal = {
          AWS = var.soar_account_id
        }
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = var.soar_account_id
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-cross-account-responder"
      Purpose     = "incident-response"
      ManagedBy   = "terraform"
    }
  )
}

resource "aws_iam_role_policy" "cross_account_responder_policy" {
  name = "${var.environment}-cross-account-responder-policy"
  role = aws_iam_role.cross_account_responder.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeVpcs",
          "ec2:DescribeAccountAttributes"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceSecurityGroups",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "ec2:Vpc" = var.allowed_vpcs
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:DeleteSnapshot",
          "ec2:DescribeSnapshots",
          "ec2:CreateTags",
          "ec2:DeleteTags"
        ]
        Resource = "arn:aws:ec2:*:${data.aws_caller_identity.current.account_id}:snapshot/*"
        Condition = {
          StringLike = {
            "ec2:ResourceTag/Purpose" = "soar-*"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListRoles",
          "iam:ListAccessKeys",
          "iam:GetUser",
          "iam:GetRole",
          "iam:GetAccessKeyLastUsed"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:UpdateAccessKey",
          "iam:DeleteAccessKey",
          "iam:CreateAccessKey",
          "iam:DeleteUser",
          "iam:AttachUserPolicy",
          "iam:DetachUserPolicy"
        ]
        Resource = "arn:aws:iam::*:user/${var.allowed_iam_users}"
        Condition = {
          StringEquals = {
            "aws:PrincipalAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:ListFunctions",
          "lambda:GetFunction",
          "lambda:InvokeFunction"
        ]
        Resource = "arn:aws:lambda:*:${data.aws_caller_identity.current.account_id}:function:soar-*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketPolicy",
          "s3:GetBucketLogging",
          "s3:PutBucketPolicy",
          "s3:PutBucketLogging"
        ]
        Resource = "arn:aws:s3:::${var.allowed_buckets}"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::${var.allowed_buckets}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:ListTrails"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings",
          "guardduty:ListDetectors"
        ]
        Resource = "arn:aws:guardduty:*:${data.aws_caller_identity.current.account_id}:detector/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/soar/incident-response/*"
      }
    ]
  })
}

# ==========================================
# VPC Access for Cross-Account Response
# ==========================================
resource "aws_security_group" "cross_account_isolation" {
  name        = "${var.environment}-soar-cross-account-isolation"
  description = "Security group for SOAR cross-account incident response"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow SOAR from SOAR account"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-cross-account-isolation-sg"
      Purpose     = "soar-response"
      ManagedBy   = "terraform"
    }
  )
}

# ==========================================
# External ID for Cross-Account Access
# ==========================================
resource "aws_ssm_parameter" "cross_account_external_id" {
  name        = "/soar/${var.environment}/cross-account/external-id"
  description = "External ID for cross-account role assumption"
  type        = "SecureString"
  value       = var.external_id

  tags = merge(
    var.tags,
    {
      Name        = "cross-account-external-id"
      Purpose     = "cross-account-access"
      ManagedBy   = "terraform"
    }
  )
}

# ==========================================
# CloudWatch Events for Cross-Account
# ==========================================
resource "aws_cloudwatch_event_rule" "cross_account_guardduty" {
  name        = "${var.environment}-cross-account-guardduty-events"
  description = "Forward GuardDuty findings to SOAR account"
  event_pattern = jsonencode({
    "source" : ["aws.guardduty"],
    "detail-type" : ["GuardDuty Finding"]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-guardduty-events"
      Purpose     = "cross-account-monitoring"
    }
  )
}

resource "aws_cloudwatch_event_target" "cross_account_guardduty_sns" {
  rule      = aws_cloudwatch_event_rule.cross_account_guardduty.name
  target_id = "SOARSNS"
  arn       = "arn:aws:sns:${var.soar_region}:${var.soar_account_id}:${var.soar_sns_topic}"
  role_arn  = aws_iam_role.cross_account_events[0].arn

  input_transformer {
    input_paths = {
      account = "$.detail.accountId"
      region  = "$.region"
      finder  = "$.detail.id"
      type    = "$.detail.type"
      sev     = "$.detail.severity"
      resource = "$.detail.resource.resourceId"
    }
    input_template = <<EOF
{
  "source_account": "<account>",
  "region": "<region>",
  "finding_id": "<finder>",
  "finding_type": "<type>",
  "severity": "<sev>",
  "resource_id": "<resource>",
  "cross_account_role_arn": "${aws_iam_role.cross_account_responder.arn}"
}
EOF
  }
}

# ==========================================
# IAM Role for CloudWatch Events
# ==========================================
resource "aws_iam_role" "cross_account_events" {
  count = var.enable_event_forwarding ? 1 : 0

  name = "${var.environment}-cross-account-events-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-events-role"
      Purpose     = "cross-account-events"
    }
  )
}

resource "aws_iam_role_policy" "cross_account_events_policy" {
  count = var.enable_event_forwarding ? 1 : 0

  name = "${var.environment}-cross-account-events-policy"
  role = aws_iam_role.cross_account_events[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = "arn:aws:sns:${var.soar_region}:${var.soar_account_id}:${var.soar_sns_topic}"
      }
    ]
  })
}

# ==========================================
# AWS Config Rules for Compliance
# ==========================================
resource "aws_config_configuration_recorder" "cross_account_config" {
  name     = "${var.environment}-soar-config-recorder"
  role_arn = aws_iam_role.cross_account_config[0].arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "cross_account_config" {
  count = var.enable_config_recording ? 1 : 0

  name = "${var.environment}-cross-account-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-config-role"
      Purpose     = "compliance-monitoring"
    }
  )
}

resource "aws_iam_role_policy" "cross_account_config_policy" {
  count = var.enable_config_recording ? 1 : 0

  name = "${var.environment}-cross-account-config-policy"
  role = aws_iam_role.cross_account_config[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "s3:ResourceTag/Purpose" = "soar-*"
          }
        }
      }
    ]
  })
}

# ==========================================
# Security Hub Integration
# ==========================================
resource "aws_securityhub_member" "cross_account_security_hub" {
  account_id = var.soar_account_id

  depends_on = [
    aws_iam_role.cross_account_responder
  ]
}

resource "aws_securityhub_invitation_accepter" "cross_account_security_hub" {
  depends_on = [aws_securityhub_member.cross_account_security_hub]

  master_id = var.soar_account_id
}
