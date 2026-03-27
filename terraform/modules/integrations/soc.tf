# Enterprise SOAR SOC Integrations Module
# Integrations with Security Operations Center tools

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
resource "aws_ssm_parameter" "slack_webhook_url" {
  count = var.slack_webhook_url != "" ? 1 : 0

  name        = "/soar/${var.environment}/slack/webhook_url"
  description = "Slack webhook URL for SOAR notifications"
  type        = "SecureString"
  value       = var.slack_webhook_url

  tags = merge(
    var.tags,
    {
      Name        = "slack-webhook-url"
      Integration = "slack"
    }
  )
}

resource "aws_sfn_state_machine" "slack_notification" {
  count = var.slack_enabled ? 1 : 0

  name     = "${var.environment}-soar-slack-notification"
  role_arn = aws_iam_role.soc_integration_role[0].arn
  type     = "EXPRESS"

  definition = <<EOF
{
  "Comment": "SOAR Slack Notification Workflow",
  "StartAt": "FormatMessage",
  "States": {
    "FormatMessage": {
      "Type": "Pass",
      "Parameters": {
        "formatted_message": {
          "blocks": [
            {
              "type": "header",
              "text": {
                "type": "plain_text",
                "text": "SOAR Alert: ${var.alert_emoji}"
              }
            },
            {
              "type": "section",
              "fields": [
                {
                  "type": "mrkdwn",
                  "text": "*Finding:* ${"$.finding_id"}"
                },
                {
                  "type": "mrkdwn",
                  "text": "*Severity:* ${"$.severity"}"
                }
              ]
            },
            {
              "type": "section",
              "text": {
                "type": "mrkdwn",
                "text": "*Action:* ${"$.action_taken"}"
              }
            }
          ]
        }
      },
      "Next": "SendToSlack"
    },
    "SendToSlack": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.slack_notifier[0].function_name}",
        "Payload": {
          "webhook_url": "${var.slack_webhook_url}",
          "message": "${$.formatted_message}"
        }
      },
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-slack-notification-sfn"
      Integration = "slack"
    }
  )
}

resource "aws_lambda_function" "slack_notifier" {
  count = var.slack_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-slack-notifier"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/slack_notifier.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      LOG_LEVEL        = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-slack-notifier"
    }
  )
}

# ==========================================
# Jira Integration
# ==========================================
resource "aws_ssm_parameter" "jira_api_token" {
  count = var.jira_enabled ? 1 : 0

  name        = "/soar/${var.environment}/jira/api_token"
  description = "Jira API token for SOAR"
  type        = "SecureString"
  value       = var.jira_api_token

  tags = merge(
    var.tags,
    {
      Name        = "jira-api-token"
      Integration = "jira"
    }
  )
}

resource "aws_lambda_function" "jira_creator" {
  count = var.jira_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-jira-creator"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/jira_manager.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      JIRA_URL         = var.jira_url
      JIRA_USERNAME    = var.jira_username
      JIRA_PROJECT_KEY = var.jira_project_key
      LOG_LEVEL       = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-jira-creator"
    }
  )
}

resource "aws_sfn_state_machine" "jira_ticket_creation" {
  count = var.jira_enabled ? 1 : 0

  name     = "${var.environment}-soar-jira-ticket"
  role_arn = aws_iam_role.soc_integration_role[0].arn
  type     = "EXPRESS"

  definition = <<EOF
{
  "Comment": "SOAR Jira Ticket Creation Workflow",
  "StartAt": "CreateTicket",
  "States": {
    "CreateTicket": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.jira_creator[0].function_name}",
        "Payload": {
          "finding_id": "${$.finding_id}",
          "severity": "${$.severity}",
          "description": "${$.description}",
          "instance_id": "${$.instance_id}",
          "action_taken": "${$.action_taken}"
        }
      },
      "Next": "AttachLabels"
    },
    "AttachLabels": {
      "Type": "Pass",
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-jira-ticket-sfn"
      Integration = "jira"
    }
  )
}

# ==========================================
# Splunk Integration
# ==========================================
resource "aws_ssm_parameter" "splunk_hec_token" {
  count = var.splunk_enabled ? 1 : 0

  name        = "/soar/${var.environment}/splunk/hec_token"
  description = "Splunk HEC token for SOAR"
  type        = "SecureString"
  value       = var.splunk_hec_token

  tags = merge(
    var.tags,
    {
      Name        = "splunk-hec-token"
      Integration = "splunk"
    }
  )
}

resource "aws_lambda_function" "splunk_forwarder" {
  count = var.splunk_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-splunk-forwarder"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/siem_forwarder.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SPLUNK_HEC_URL  = var.splunk_hec_url
      SPLUNK_INDEX    = var.splunk_index
      LOG_LEVEL       = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-splunk-forwarder"
    }
  )
}

resource "aws_sfn_state_machine" "splunk_forwarding" {
  count = var.splunk_enabled ? 1 : 0

  name     = "${var.environment}-soar-splunk-forwarding"
  role_arn = aws_iam_role.soc_integration_role[0].arn
  type     = "EXPRESS"

  definition = <<EOF
{
  "Comment": "SOAR Splunk Forwarding Workflow",
  "StartAt": "FormatEvent",
  "States": {
    "FormatEvent": {
      "Type": "Pass",
      "Parameters": {
        "splunk_event": {
          "source": "aws-soar",
          "sourcetype": "soar:incident",
          "index": "${var.splunk_index}",
          "event": "${$}"
        }
      },
      "Next": "ForwardToSplunk"
    },
    "ForwardToSplunk": {
      "Type": "Task",
      "Resource": "arn:aws:states:::lambda:invoke",
      "Parameters": {
        "FunctionName": "${aws_lambda_function.splunk_forwarder[0].function_name}",
        "Payload": "${$.splunk_event}"
      },
      "End": true
    }
  }
}
EOF

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-splunk-forwarding-sfn"
      Integration = "splunk"
    }
  )
}

# ==========================================
# PagerDuty Integration
# ==========================================
resource "aws_ssm_parameter" "pagerduty_routing_key" {
  count = var.pagerduty_enabled ? 1 : 0

  name        = "/soar/${var.environment}/pagerduty/routing_key"
  description = "PagerDuty routing key for SOAR"
  type        = "SecureString"
  value       = var.pagerduty_routing_key

  tags = merge(
    var.tags,
    {
      Name        = "pagerduty-routing-key"
      Integration = "pagerduty"
    }
  )
}

resource "aws_lambda_function" "pagerduty_alerter" {
  count = var.pagerduty_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-pagerduty-alerter"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/pagerduty_alerter.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      PAGERDUTY_ROUTING_KEY = var.pagerduty_routing_key
      PAGERDUTY_SERVICE_ID = var.pagerduty_service_id
      LOG_LEVEL            = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-pagerduty-alerter"
    }
  )
}

# ==========================================
# Microsoft Teams Integration
# ==========================================
resource "aws_ssm_parameter" "teams_webhook_url" {
  count = var.teams_enabled ? 1 : 0

  name        = "/soar/${var.environment}/teams/webhook_url"
  description = "Microsoft Teams webhook URL for SOAR notifications"
  type        = "SecureString"
  value       = var.teams_webhook_url

  tags = merge(
    var.tags,
    {
      Name        = "teams-webhook-url"
      Integration = "teams"
    }
  )
}

resource "aws_lambda_function" "teams_notifier" {
  count = var.teams_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-teams-notifier"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/teams_notifier.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      TEAMS_WEBHOOK_URL = var.teams_webhook_url
      LOG_LEVEL        = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-teams-notifier"
    }
  )
}

# ==========================================
# Threat Intelligence Integration
# ==========================================
resource "aws_ssm_parameter" "virustotal_api_key" {
  count = var.threat_intel_enabled ? 1 : 0

  name        = "/soar/${var.environment}/threat_intel/virustotal_api_key"
  description = "VirusTotal API key for SOAR"
  type        = "SecureString"
  value       = var.virustotal_api_key

  tags = merge(
    var.tags,
    {
      Name        = "virustotal-api-key"
      Integration = "threat-intel"
    }
  )
}

resource "aws_ssm_parameter" "abuseipdb_api_key" {
  count = var.threat_intel_enabled ? 1 : 0

  name        = "/soar/${var.environment}/threat_intel/abuseipdb_api_key"
  description = "AbuseIPDB API key for SOAR"
  type        = "SecureString"
  value       = var.abuseipdb_api_key

  tags = merge(
    var.tags,
    {
      Name        = "abuseipdb-api-key"
      Integration = "threat-intel"
    }
  )
}

resource "aws_lambda_function" "threat_intel_enricher" {
  count = var.threat_intel_enabled ? 1 : 0

  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "${var.environment}-soar-threat-intel-enricher"
  role             = aws_iam_role.soc_integration_role[0].arn
  handler          = "integrations/intel.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 60

  environment {
    variables = {
      VIRUSTOTAL_API_KEY = var.virustotal_api_key
      ABUSEIPDB_API_KEY  = var.abuseipdb_api_key
      LOG_LEVEL         = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-threat-intel-enricher"
    }
  )
}

# ==========================================
# IAM Role for SOC Integrations
# ==========================================
resource "aws_iam_role" "soc_integration_role" {
  count = var.slack_enabled || var.jira_enabled || var.splunk_enabled || var.pagerduty_enabled || var.teams_enabled || var.threat_intel_enabled ? 1 : 0

  name = "${var.environment}-soar-soc-integration-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "states.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-soc-integration-role"
    }
  )
}

resource "aws_iam_role_policy" "soc_integration_policy" {
  count = var.slack_enabled || var.jira_enabled || var.splunk_enabled || var.pagerduty_enabled || var.teams_enabled || var.threat_intel_enabled ? 1 : 0

  name = "${var.environment}-soar-soc-integration-policy"
  role = aws_iam_role.soc_integration_role[0].id

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
          "arn:aws:ssm:*:*:parameter/soar/${var.environment}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "http:POST",
          "http:GET",
          "http:PUT"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==========================================
# Secrets Manager for API Keys
# ==========================================
resource "aws_secretsmanager_secret" "soc_credentials" {
  count = var.use_secrets_manager ? 1 : 0

  name        = "/soar/${var.environment}/credentials"
  description = "SOAR SOC integrations credentials"

  recovery_window_in_days = 7

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-soc-credentials"
    }
  )
}

resource "aws_secretsmanager_secret_version" "soc_credentials" {
  count = var.use_secrets_manager ? 1 : 0

  secret_id = aws_secretsmanager_secret.soc_credentials[0].id

  secret_string = jsonencode({
    slack_webhook_url     = var.slack_webhook_url
    jira_url              = var.jira_url
    jira_username         = var.jira_username
    jira_api_token        = var.jira_api_token
    splunk_hec_url        = var.splunk_hec_url
    splunk_hec_token      = var.splunk_hec_token
    pagerduty_routing_key = var.pagerduty_routing_key
    teams_webhook_url     = var.teams_webhook_url
    virustotal_api_key    = var.virustotal_api_key
    abuseipdb_api_key     = var.abuseipdb_api_key
  })

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-soc-credentials-version"
    }
  )
}
