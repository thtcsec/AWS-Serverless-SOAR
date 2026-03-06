# Enterprise SOAR Security Module
# Multi-account security architecture with cross-account roles

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
# SOAR Central Security Account IAM Roles
# ==========================================

# Main SOAR execution role with cross-account access
resource "aws_iam_role" "soar_central_role" {
  name = "${var.environment}-soar-central-execution-role"
  description = "Central SOAR role with cross-account incident response capabilities"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = [
            "lambda.amazonaws.com",
            "states.amazonaws.com",
            "ecs-tasks.amazonaws.com"
          ]
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-central-role"
      Environment = var.environment
      Purpose     = "central-soar-execution"
    }
  })
}

# Cross-account SOAR responder role
resource "aws_iam_role" "soar_cross_account_responder" {
  name = "${var.environment}-soar-cross-account-responder"
  description = "Role for cross-account incident response operations"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = [
            "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/${var.environment}-soar-central-execution-role"
          ]
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cross_account_external_id
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-cross-account-responder"
      Environment = var.environment
      Purpose     = "cross-account-response"
    }
  })
}

# ==========================================
# SOAR Cross-Account Policies
# ==========================================

# Central SOAR policy
resource "aws_iam_policy" "soar_central_policy" {
  name = "${var.environment}-soar-central-policy"
  description = "Comprehensive SOAR policy for central security account"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # Cross-account STS operations
          "sts:AssumeRole",
          "sts:GetCallerIdentity"
        ]
        Resource = [
          "arn:aws:iam::*:role/*-soar-cross-account-responder"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          # EventBridge operations
          "events:PutRule",
          "events:PutTargets",
          "events:DeleteRule",
          "events:RemoveTargets",
          "events:DescribeRule"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # SQS operations
          "sqs:CreateQueue",
          "sqs:DeleteQueue",
          "sqs:GetQueueAttributes",
          "sqs:SetQueueAttributes",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:SendMessage"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Step Functions operations
          "states:CreateStateMachine",
          "states:DeleteStateMachine",
          "states:DescribeStateMachine",
          "states:StartExecution",
          "states:StopExecution",
          "states:GetExecutionHistory"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Lambda operations
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:InvokeFunction",
          "lambda:DeleteFunction",
          "lambda:GetFunction"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # ECS operations
          "ecs:CreateCluster",
          "ecs:RegisterTaskDefinition",
          "ecs:CreateService",
          "ecs:UpdateService",
          "ecs:RunTask"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # SNS operations
          "sns:CreateTopic",
          "sns:DeleteTopic",
          "sns:Publish",
          "sns:Subscribe"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Logging and monitoring
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "cloudwatch:PutMetricData",
          "cloudwatch:CreateAlarm"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # GuardDuty operations
          "guardduty:CreateDetector",
          "guardduty:UpdateDetector",
          "guardduty:GetFindings",
          "guardduty:ListFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# Cross-account responder policy
resource "aws_iam_policy" "soar_cross_account_policy" {
  name = "${var.environment}-soar-cross-account-policy"
  description = "Policy for cross-account incident response operations"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # EC2 operations for incident response
          "ec2:DescribeInstances",
          "ec2:DescribeImages",
          "ec2:DescribeSnapshots",
          "ec2:DescribeVolumes",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:StartInstances"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # IAM operations for credential management
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:ListAttachedUserPolicies",
          "iam:ListAttachedRolePolicies",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "iam:DetachUserPolicy",
          "iam:DetachRolePolicy"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # S3 operations for data protection
          "s3:ListBucket",
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:GetBucketPolicy",
          "s3:PutBucketPolicy",
          "s3:PutBucketVersioning",
          "s3:PutBucketLogging"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # CloudTrail operations
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:LookupEvents"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # VPC operations for network isolation
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "ec2:DescribeRouteTables",
          "ec2:DescribeNetworkAcls",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          # Logging operations
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# ==========================================
# Policy Attachments
# ==========================================
resource "aws_iam_role_policy_attachment" "soar_central_policy_attach" {
  role       = aws_iam_role.soar_central_role.name
  policy_arn = aws_iam_policy.soar_central_policy.arn
}

resource "aws_iam_role_policy_attachment" "soar_cross_account_policy_attach" {
  role       = aws_iam_role.soar_cross_account_responder.name
  policy_arn = aws_iam_policy.soar_cross_account_policy.arn
}

# ==========================================
# Cross-Account Trust Relationships
# ==========================================

# Dev account access
resource "aws_iam_role" "dev_account_access" {
  count = var.enable_dev_account_access ? 1 : 0
  name  = "${var.environment}-soar-dev-account-access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.dev_account_id}:root"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cross_account_external_id
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-dev-access"
      Environment = var.environment
      Account     = "dev"
    }
  )
}

# Staging account access
resource "aws_iam_role" "staging_account_access" {
  count = var.enable_staging_account_access ? 1 : 0
  name  = "${var.environment}-soar-staging-account-access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.staging_account_id}:root"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cross_account_external_id
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-staging-access"
      Environment = var.environment
      Account     = "staging"
    }
  )
}

# Production account access
resource "aws_iam_role" "prod_account_access" {
  count = var.enable_prod_account_access ? 1 : 0
  name  = "${var.environment}-soar-prod-account-access"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${var.prod_account_id}:root"
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.cross_account_external_id
          }
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-prod-access"
      Environment = var.environment
      Account     = "production"
    }
  )
}

# ==========================================
# Security Account Configuration
# ==========================================

# GuardDuty master account configuration
resource "aws_guardduty_detector" "central_detector" {
  enable = true
  
  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-guardduty-master"
      Environment = var.environment
      Purpose     = "central-threat-detection"
    }
  )
}

# GuardDuty member account invitations
resource "aws_guardduty_member" "dev_member" {
  count                     = var.enable_dev_account_access ? 1 : 0
  detector_id              = aws_guardduty_detector.central_detector.id
  account_id               = var.dev_account_id
  email                    = var.dev_account_email
  invite                   = true
  disable_email_notification = false
  
  depends_on = [aws_guardduty_detector.central_detector]
}

resource "aws_guardduty_member" "staging_member" {
  count                     = var.enable_staging_account_access ? 1 : 0
  detector_id              = aws_guardduty_detector.central_detector.id
  account_id               = var.staging_account_id
  email                    = var.staging_account_email
  invite                   = true
  disable_email_notification = false
  
  depends_on = [aws_guardduty_detector.central_detector]
}

resource "aws_guardduty_member" "prod_member" {
  count                     = var.enable_prod_account_access ? 1 : 0
  detector_id              = aws_guardduty_detector.central_detector.id
  account_id               = var.prod_account_id
  email                    = var.prod_account_email
  invite                   = true
  disable_email_notification = false
  
  depends_on = [aws_guardduty_detector.central_detector]
}

# ==========================================
# Central Logging Configuration
# ==========================================
resource "aws_s3_bucket" "central_logs" {
  bucket = "${var.environment}-soar-central-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-central-logs"
      Environment = var.environment
      Purpose     = "centralized-logging"
    }
  )
}

resource "aws_s3_bucket_versioning" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "central_logs" {
  bucket = aws_s3_bucket.central_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Data source for current account
data "aws_caller_identity" "current" {}
