# ==========================================
# CloudWatch Dashboard — SOAR Observability
# ==========================================

resource "aws_cloudwatch_dashboard" "soar_dashboard" {
  dashboard_name = "SOAR-IncidentResponse"

  dashboard_body = jsonencode({
    widgets = [

      # ── Row 1: High-level KPIs ──
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Total Findings Processed"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "FindingsProcessed", { stat = "Sum" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Playbook Success vs Failure"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "PlaybookSuccess", { stat = "Sum", color = "#2ca02c" }],
            ["SOAR/IncidentResponse", "PlaybookFailure", { stat = "Sum", color = "#d62728" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 0
        width  = 8
        height = 6
        properties = {
          title  = "Avg Playbook Duration (ms)"
          region = var.aws_region
          stat   = "Average"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "PlaybookDuration", { stat = "Average" }]
          ]
        }
      },

      # ── Row 2: Per-playbook breakdown ──
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "EC2 Containment — Findings"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "FindingsProcessed", "Playbook", "EC2Containment"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "S3 Exfiltration — Findings"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "FindingsProcessed", "Playbook", "S3Exfiltration"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 6
        width  = 8
        height = 6
        properties = {
          title  = "IAM Compromise — Findings"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "FindingsProcessed", "Playbook", "IAMCompromise"]
          ]
        }
      },

      # ── Row 3: Duration per playbook ──
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Playbook Duration by Type (ms)"
          region = var.aws_region
          stat   = "Average"
          period = 300
          view   = "timeSeries"
          metrics = [
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "EC2Containment", { color = "#1f77b4" }],
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "S3Exfiltration", { color = "#ff7f0e" }],
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "IAMCompromise", { color = "#9467bd" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 12
        width  = 12
        height = 6
        properties = {
          title  = "Playbook P99 Duration (ms)"
          region = var.aws_region
          stat   = "p99"
          period = 300
          metrics = [
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "EC2Containment"],
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "S3Exfiltration"],
            ["SOAR/IncidentResponse", "PlaybookDuration", "Playbook", "IAMCompromise"]
          ]
        }
      },

      # ── Row 4: Lambda metrics ──
      {
        type   = "metric"
        x      = 0
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Invocations"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "soar-engine"]
          ]
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Errors"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/Lambda", "Errors", "FunctionName", "soar-engine", { color = "#d62728" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 18
        width  = 8
        height = 6
        properties = {
          title  = "Lambda Duration (avg ms)"
          region = var.aws_region
          stat   = "Average"
          period = 300
          metrics = [
            ["AWS/Lambda", "Duration", "FunctionName", "soar-engine"]
          ]
        }
      },

      # ── Row 5: SQS Dead Letter Queue ──
      {
        type   = "metric"
        x      = 0
        y      = 24
        width  = 12
        height = 6
        properties = {
          title  = "SQS — Messages Visible (DLQ)"
          region = var.aws_region
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", "soar-dlq", { color = "#d62728" }]
          ]
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 24
        width  = 12
        height = 6
        properties = {
          title  = "SQS — Messages Processed"
          region = var.aws_region
          stat   = "Sum"
          period = 300
          metrics = [
            ["AWS/SQS", "NumberOfMessagesReceived", "QueueName", "soar-queue"],
            ["AWS/SQS", "NumberOfMessagesDeleted", "QueueName", "soar-queue"]
          ]
        }
      }
    ]
  })
}

# ==========================================
# CloudWatch Alarms
# ==========================================

resource "aws_cloudwatch_metric_alarm" "playbook_failure_alarm" {
  alarm_name          = "SOAR-PlaybookFailure"
  alarm_description   = "Triggers when any SOAR playbook fails"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "PlaybookFailure"
  namespace           = "SOAR/IncidentResponse"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_alert_topic_arn]

  tags = {
    Environment = "production"
    Service     = "soar"
  }
}

resource "aws_cloudwatch_metric_alarm" "dlq_messages_alarm" {
  alarm_name          = "SOAR-DLQ-Messages"
  alarm_description   = "Triggers when messages land in the Dead Letter Queue"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Maximum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    QueueName = "soar-dlq"
  }

  alarm_actions = [var.sns_alert_topic_arn]

  tags = {
    Environment = "production"
    Service     = "soar"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_error_alarm" {
  alarm_name          = "SOAR-LambdaErrors"
  alarm_description   = "Triggers when the SOAR Lambda function encounters errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = "soar-engine"
  }

  alarm_actions = [var.sns_alert_topic_arn]

  tags = {
    Environment = "production"
    Service     = "soar"
  }
}

resource "aws_cloudwatch_metric_alarm" "high_playbook_duration" {
  alarm_name          = "SOAR-HighPlaybookDuration"
  alarm_description   = "Triggers when playbook execution exceeds 30 seconds"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "PlaybookDuration"
  namespace           = "SOAR/IncidentResponse"
  period              = 300
  statistic           = "Average"
  threshold           = 30000
  treat_missing_data  = "notBreaching"
  alarm_actions       = [var.sns_alert_topic_arn]

  tags = {
    Environment = "production"
    Service     = "soar"
  }
}
