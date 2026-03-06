# Enterprise SOAR Integrations Module
# Slack, Jira/ServiceNow, and SIEM integrations

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
# Slack Integration
# ==========================================
resource "aws_iam_role" "slack_integration_role" {
  name = "${var.environment}-soar-slack-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-slack-role"
      Environment = var.environment
      Purpose     = "slack-integration"
    }
  )
}

resource "aws_iam_policy" "slack_integration_policy" {
  name = "${var.environment}-soar-slack-integration-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/soar/slack/*",
          "arn:aws:ssm:*:*:parameter/soar/jira/*",
          "arn:aws:ssm:*:*:parameter/soar/siem/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "slack_integration_policy_attach" {
  role       = aws_iam_role.slack_integration_role.name
  policy_arn = aws_iam_policy.slack_integration_policy.arn
}

# Slack notification Lambda
data "archive_file" "slack_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../../src/integrations/slack_notifier.py"
  output_path = "${path.module}/slack_lambda.zip"
}

resource "aws_lambda_function" "slack_notifier" {
  filename         = data.archive_file.slack_lambda_zip.output_path
  function_name    = "${var.environment}-soar-slack-notifier"
  role             = aws_iam_role.slack_integration_role.arn
  handler          = "slack_notifier.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.slack_lambda_zip.output_base64sha256
  memory_size      = 256
  timeout          = 60

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-slack-notifier"
      Environment = var.environment
      Purpose     = "slack-notifications"
    }
  )
}

resource "aws_cloudwatch_log_group" "slack_logs" {
  name              = "/aws/lambda/${aws_lambda_function.slack_notifier.function_name}"
  retention_in_days = 30

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-slack-logs"
      Environment = var.environment
    }
  )
}

# ==========================================
# Jira Integration
# ==========================================
resource "aws_iam_role" "jira_integration_role" {
  name = "${var.environment}-soar-jira-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-role"
      Environment = var.environment
      Purpose     = "jira-integration"
    }
  )
}

resource "aws_iam_policy" "jira_integration_policy" {
  name = "${var.environment}-soar-jira-integration-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/soar/jira/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "jira_integration_policy_attach" {
  role       = aws_iam_role.jira_integration_role.name
  policy_arn = aws_iam_policy.jira_integration_policy.arn
}

# Jira ticket management Lambda
data "archive_file" "jira_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../../src/integrations/jira_manager.py"
  output_path = "${path.module}/jira_lambda.zip"
}

resource "aws_lambda_function" "jira_manager" {
  filename         = data.archive_file.jira_lambda_zip.output_path
  function_name    = "${var.environment}-soar-jira-manager"
  role             = aws_iam_role.jira_integration_role.arn
  handler          = "jira_manager.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.jira_lambda_zip.output_base64sha256
  memory_size      = 256
  timeout          = 120

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-manager"
      Environment = var.environment
      Purpose     = "jira-ticket-management"
    }
  )
}

resource "aws_cloudwatch_log_group" "jira_logs" {
  name              = "/aws/lambda/${aws_lambda_function.jira_manager.function_name}"
  retention_in_days = 30

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-logs"
      Environment = var.environment
    }
  )
}

# ==========================================
# SIEM Integration
# ==========================================
resource "aws_iam_role" "siem_integration_role" {
  name = "${var.environment}-soar-siem-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-role"
      Environment = var.environment
      Purpose     = "siem-integration"
    }
  )
}

resource "aws_iam_policy" "siem_integration_policy" {
  name = "${var.environment}-soar-siem-integration-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = [
          "arn:aws:ssm:*:*:parameter/soar/siem/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "siem_integration_policy_attach" {
  role       = aws_iam_role.siem_integration_role.name
  policy_arn = aws_iam_policy.siem_integration_policy.arn
}

# SIEM forwarder Lambda
data "archive_file" "siem_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../../src/integrations/siem_forwarder.py"
  output_path = "${path.module}/siem_lambda.zip"
}

resource "aws_lambda_function" "siem_forwarder" {
  filename         = data.archive_file.siem_lambda_zip.output_path
  function_name    = "${var.environment}-soar-siem-forwarder"
  role             = aws_iam_role.siem_integration_role.arn
  handler          = "siem_forwarder.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.siem_lambda_zip.output_base64sha256
  memory_size      = 256
  timeout          = 120

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-forwarder"
      Environment = var.environment
      Purpose     = "siem-data-forwarding"
    }
  )
}

resource "aws_cloudwatch_log_group" "siem_logs" {
  name              = "/aws/lambda/${aws_lambda_function.siem_forwarder.function_name}"
  retention_in_days = 30

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-logs"
      Environment = var.environment
    }
  )
}

# ==========================================
# Integration Parameters (Secure Storage)
# ==========================================

# Slack webhook URL
resource "aws_ssm_parameter" "slack_webhook_url" {
  count = var.enable_slack_integration ? 1 : 0
  name  = "/soar/slack/webhook_url"
  type  = "SecureString"
  value = var.slack_webhook_url

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-slack-webhook"
      Environment = var.environment
    }
  )
}

# Jira configuration
resource "aws_ssm_parameter" "jira_url" {
  count = var.enable_jira_integration ? 1 : 0
  name  = "/soar/jira/url"
  type  = "SecureString"
  value = var.jira_url

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-url"
      Environment = var.environment
    }
  )
}

resource "aws_ssm_parameter" "jira_username" {
  count = var.enable_jira_integration ? 1 : 0
  name  = "/soar/jira/username"
  type  = "SecureString"
  value = var.jira_username

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-username"
      Environment = var.environment
    }
  )
}

resource "aws_ssm_parameter" "jira_api_token" {
  count = var.enable_jira_integration ? 1 : 0
  name  = "/soar/jira/api_token"
  type  = "SecureString"
  value = var.jira_api_token

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-token"
      Environment = var.environment
    }
  )
}

# SIEM configuration
resource "aws_ssm_parameter" "siem_endpoint" {
  count = var.enable_siem_integration ? 1 : 0
  name  = "/soar/siem/endpoint"
  type  = "SecureString"
  value = var.siem_endpoint

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-endpoint"
      Environment = var.environment
    }
  )
}

resource "aws_ssm_parameter" "siem_api_key" {
  count = var.enable_siem_integration ? 1 : 0
  name  = "/soar/siem/api_key"
  type  = "SecureString"
  value = var.siem_api_key

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-api-key"
      Environment = var.environment
    }
  )
}

# ==========================================
# EventBridge Rules for Integrations
# ==========================================

# Trigger Slack notifications
resource "aws_cloudwatch_event_rule" "slack_notifications" {
  count = var.enable_slack_integration ? 1 : 0
  name  = "${var.environment}-soar-slack-notifications"

  event_pattern = jsonencode({
    source = ["soar.workflow"]
    detail-type = [
      "IncidentDetected",
      "InstanceIsolated",
      "SnapshotCreated",
      "InstanceTerminated",
      "ForensicsCompleted"
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-slack-rule"
      Environment = var.environment
      Purpose     = "slack-notifications"
    }
  )
}

resource "aws_cloudwatch_event_target" "slack_target" {
  count     = var.enable_slack_integration ? 1 : 0
  rule      = aws_cloudwatch_event_rule.slack_notifications[0].name
  target_id = "SlackNotifier"
  arn       = aws_lambda_function.slack_notifier.arn
}

resource "aws_lambda_permission" "allow_slack_eventbridge" {
  count         = var.enable_slack_integration ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridgeSlack"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_notifier.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.slack_notifications[0].arn
}

# Trigger Jira ticket creation
resource "aws_cloudwatch_event_rule" "jira_tickets" {
  count = var.enable_jira_integration ? 1 : 0
  name  = "${var.environment}-soar-jira-tickets"

  event_pattern = jsonencode({
    source = ["soar.workflow"]
    detail-type = [
      "IncidentDetected",
      "InstanceIsolated"
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-jira-rule"
      Environment = var.environment
      Purpose     = "jira-ticket-creation"
    }
  )
}

resource "aws_cloudwatch_event_target" "jira_target" {
  count     = var.enable_jira_integration ? 1 : 0
  rule      = aws_cloudwatch_event_rule.jira_tickets[0].name
  target_id = "JiraManager"
  arn       = aws_lambda_function.jira_manager.arn
}

resource "aws_lambda_permission" "allow_jira_eventbridge" {
  count         = var.enable_jira_integration ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridgeJira"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.jira_manager.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.jira_tickets[0].arn
}

# Trigger SIEM forwarding
resource "aws_cloudwatch_event_rule" "siem_forwarding" {
  count = var.enable_siem_integration ? 1 : 0
  name  = "${var.environment}-soar-siem-forwarding"

  event_pattern = jsonencode({
    source = ["soar.workflow"]
    detail-type = [
      "IncidentDetected",
      "InstanceIsolated",
      "SnapshotCreated",
      "InstanceTerminated",
      "ForensicsCompleted"
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-siem-rule"
      Environment = var.environment
      Purpose     = "siem-data-forwarding"
    }
  )
}

resource "aws_cloudwatch_event_target" "siem_target" {
  count     = var.enable_siem_integration ? 1 : 0
  rule      = aws_cloudwatch_event_rule.siem_forwarding[0].name
  target_id = "SIEMForwarder"
  arn       = aws_lambda_function.siem_forwarder.arn
}

resource "aws_lambda_permission" "allow_siem_eventbridge" {
  count         = var.enable_siem_integration ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridgeSIEM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.siem_forwarder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.siem_forwarding[0].arn
}
