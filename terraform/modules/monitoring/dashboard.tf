# AWS SOAR — CloudWatch Monitoring Dashboard
# Provides centralized visibility into SOAR platform health,
# incident metrics, and mean time to respond (MTTR).

# -------------------------------------------------------------------
# Variables
# -------------------------------------------------------------------
variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "lambda_function_names" {
  description = "List of Lambda function names to monitor"
  type        = list(string)
  default     = ["soar-ec2-containment", "soar-s3-exfiltration", "soar-iam-compromise"]
}

variable "sqs_queue_name" {
  description = "SQS queue name for incident messages"
  type        = string
  default     = "soar-incident-queue"
}

variable "dlq_queue_name" {
  description = "Dead Letter Queue name"
  type        = string
  default     = "soar-incident-dlq"
}

variable "step_function_arn" {
  description = "ARN of the Step Functions state machine"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -------------------------------------------------------------------
# CloudWatch Dashboard
# -------------------------------------------------------------------
resource "aws_cloudwatch_dashboard" "soar_dashboard" {
  dashboard_name = "SOAR-Platform-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [

      # --- Row 1: Incident Volume ---
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Incident Volume (Lambda Invocations)"
          view    = "timeSeries"
          stacked = true
          metrics = [for fn in var.lambda_function_names : [
            "AWS/Lambda", "Invocations",
            "FunctionName", fn,
            { stat = "Sum", period = 300 }
          ]]
          region = data.aws_region.current.name
        }
      },

      # --- Row 1: Error Rate ---
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "Lambda Error Rate"
          view    = "timeSeries"
          stacked = false
          metrics = [for fn in var.lambda_function_names : [
            "AWS/Lambda", "Errors",
            "FunctionName", fn,
            { stat = "Sum", period = 300, color = "#d13212" }
          ]]
          region = data.aws_region.current.name
        }
      },

      # --- Row 2: Lambda Duration (MTTR Proxy) ---
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Response Duration / MTTR (ms)"
          view    = "timeSeries"
          stacked = false
          metrics = [for fn in var.lambda_function_names : [
            "AWS/Lambda", "Duration",
            "FunctionName", fn,
            { stat = "Average", period = 300 }
          ]]
          region = data.aws_region.current.name
        }
      },

      # --- Row 2: SQS Queue Depth ---
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "SQS Queue Depth (Pending Incidents)"
          view    = "timeSeries"
          stacked = false
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible",
             "QueueName", var.sqs_queue_name,
             { stat = "Maximum", period = 60 }],
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible",
             "QueueName", var.dlq_queue_name,
             { stat = "Maximum", period = 60, color = "#d13212" }]
          ]
          region = data.aws_region.current.name
        }
      },

      # --- Row 3: Step Functions Execution Status ---
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 8
        height = 6
        properties = {
          title   = "Step Functions — Execution Status"
          view    = "timeSeries"
          stacked = true
          metrics = [
            ["AWS/States", "ExecutionsSucceeded",
             "StateMachineArn", var.step_function_arn,
             { stat = "Sum", period = 300, color = "#2ca02c" }],
            ["AWS/States", "ExecutionsFailed",
             "StateMachineArn", var.step_function_arn,
             { stat = "Sum", period = 300, color = "#d13212" }],
            ["AWS/States", "ExecutionsTimedOut",
             "StateMachineArn", var.step_function_arn,
             { stat = "Sum", period = 300, color = "#ff7f0e" }]
          ]
          region = data.aws_region.current.name
        }
      },

      # --- Row 3: SLO/SLI Summary ---
      {
        type   = "metric"
        x      = 8
        y      = 12
        width  = 8
        height = 6
        properties = {
          title   = "Playbook Success Rate (SLI)"
          view    = "singleValue"
          metrics = [
            ["AWS/Lambda", "Invocations",
             "FunctionName", var.lambda_function_names[0],
             { stat = "Sum", period = 86400, label = "Total Invocations" }],
            ["AWS/Lambda", "Errors",
             "FunctionName", var.lambda_function_names[0],
             { stat = "Sum", period = 86400, label = "Total Errors", color = "#d13212" }]
          ]
          region = data.aws_region.current.name
        }
      },

      # --- Row 3: Throttles ---
      {
        type   = "metric"
        x      = 16
        y      = 12
        width  = 8
        height = 6
        properties = {
          title   = "Lambda Throttles"
          view    = "singleValue"
          metrics = [for fn in var.lambda_function_names : [
            "AWS/Lambda", "Throttles",
            "FunctionName", fn,
            { stat = "Sum", period = 86400 }
          ]]
          region = data.aws_region.current.name
        }
      }
    ]
  })
}

# -------------------------------------------------------------------
# CloudWatch Alarms
# -------------------------------------------------------------------
resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each = toset(var.lambda_function_names)

  alarm_name          = "soar-${each.value}-errors-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "SOAR Lambda ${each.value} has errors"
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = each.value
  }

  tags = merge(var.tags, {
    Component = "soar-monitoring"
  })
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages" {
  alarm_name          = "soar-dlq-messages-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "SOAR Dead Letter Queue has unprocessed messages"
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = var.dlq_queue_name
  }

  tags = merge(var.tags, {
    Component = "soar-monitoring"
  })
}

# -------------------------------------------------------------------
# Data Sources
# -------------------------------------------------------------------
data "aws_region" "current" {}

# -------------------------------------------------------------------
# Outputs
# -------------------------------------------------------------------
output "dashboard_arn" {
  description = "ARN of the SOAR monitoring dashboard"
  value       = aws_cloudwatch_dashboard.soar_dashboard.dashboard_arn
}
