# Enterprise SOAR Events Module
# EventBridge integration with message queue buffering

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
# EventBridge Rules for Security Events
# ==========================================
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${var.environment}-soar-guardduty-findings"
  description = "Capture GuardDuty findings for SOAR processing"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      resource = {
        resourceType = ["Instance"]
      }
    }
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-guardduty-rule"
      Environment = var.environment
      Purpose     = "security-event-routing"
    }
  )
}

resource "aws_cloudwatch_event_rule" "cloudtrail_iam_events" {
  name        = "${var.environment}-soar-cloudtrail-iam"
  description = "Capture CloudTrail IAM events for SOAR processing"

  event_pattern = jsonencode({
    source = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "CreateUser",
        "CreateAccessKey",
        "AddUserToGroup",
        "AttachUserPolicy",
        "CreateRole",
        "AttachRolePolicy"
      ]
    }
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-cloudtrail-iam-rule"
      Environment = var.environment
      Purpose     = "security-event-routing"
    }
  )
}

resource "aws_cloudwatch_event_rule" "s3_data_events" {
  name        = "${var.environment}-soar-s3-data-events"
  description = "Capture S3 data events for potential exfiltration detection"

  event_pattern = jsonencode({
    source = ["aws.s3"]
    detail-type = ["Object Created", "Object Accessed"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName = [
        "GetObject",
        "ListObjects",
        "DownloadFile"
      ]
    }
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-s3-events-rule"
      Environment = var.environment
      Purpose     = "security-event-routing"
    }
  )
}

# ==========================================
# EventBridge Targets - Send to SQS
# ==========================================
resource "aws_cloudwatch_event_target" "guardduty_to_sqs" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "GuarddutyToSQS"
  arn       = var.main_queue_arn
  
  # Transform the event for SQS processing
  input_transformer = {
    input_paths = {
      source = "$.source"
      detailType = "$.detail-type"
      detail = "$.detail"
      time = "$.time"
      id = "$.id"
      account = "$.account"
      region = "$.region"
    }
    input_template = <<EOF
{
  "event_source": <source>,
  "event_type": <detailType>,
  "event_time": <time>,
  "event_id": <id>,
  "account": <account>,
  "region": <region>,
  "finding": <detail>,
  "routing_timestamp": "$$.time"
}
EOF
  }
}

resource "aws_cloudwatch_event_target" "cloudtrail_to_sqs" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_iam_events.name
  target_id = "CloudTrailToSQS"
  arn       = var.main_queue_arn
  
  input_transformer = {
    input_paths = {
      source = "$.source"
      detailType = "$.detail-type"
      detail = "$.detail"
      time = "$.time"
      id = "$.id"
      account = "$.account"
      region = "$.region"
    }
    input_template = <<EOF
{
  "event_source": <source>,
  "event_type": <detailType>,
  "event_time": <time>,
  "event_id": <id>,
  "account": <account>,
  "region": <region>,
  "event": <detail>,
  "routing_timestamp": "$$.time"
}
EOF
  }
}

resource "aws_cloudwatch_event_target" "s3_to_sqs" {
  rule      = aws_cloudwatch_event_rule.s3_data_events.name
  target_id = "S3ToSQS"
  arn       = var.main_queue_arn
  
  input_transformer = {
    input_paths = {
      source = "$.source"
      detailType = "$.detail-type"
      detail = "$.detail"
      time = "$.time"
      id = "$.id"
      account = "$.account"
      region = "$.region"
    }
    input_template = <<EOF
{
  "event_source": <source>,
  "event_type": <detailType>,
  "event_time": <time>,
  "event_id": <id>,
  "account": <account>,
  "region": <region>,
  "event": <detail>,
  "routing_timestamp": "$$.time"
}
EOF
  }
}

# ==========================================
# EventBridge Permissions
# ==========================================
resource "aws_cloudwatch_event_rule" "step_function_trigger" {
  name        = "${var.environment}-soar-step-function-trigger"
  description = "Trigger Step Functions from SQS messages"

  event_pattern = jsonencode({
    source = ["aws.sqs"]
    detail-type = ["SQS Message"]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-sfn-trigger"
      Environment = var.environment
      Purpose     = "workflow-trigger"
    }
  )
}

# ==========================================
# Lambda for Queue Processing
# ==========================================
resource "aws_iam_role" "queue_processor_role" {
  name = "${var.environment}-soar-queue-processor-role"

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
      Name        = "${var.environment}-soar-queue-processor-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_policy" "queue_processor_policy" {
  name = "${var.environment}-soar-queue-processor-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = [
          var.main_queue_arn,
          var.dlq_arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "states:StartExecution",
          "states:DescribeExecution"
        ]
        Resource = var.step_function_arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "queue_processor_policy_attach" {
  role       = aws_iam_role.queue_processor_role.name
  policy_arn = aws_iam_policy.queue_processor_policy.arn
}

# Archive the queue processor Lambda
data "archive_file" "queue_processor_zip" {
  type        = "zip"
  source_file = "${path.module}/../../src/queue_processor.py"
  output_path = "${path.module}/queue_processor.zip"
}

resource "aws_lambda_function" "queue_processor" {
  filename         = data.archive_file.queue_processor_zip.output_path
  function_name    = "${var.environment}-soar-queue-processor"
  role             = aws_iam_role.queue_processor_role.arn
  handler          = "queue_processor.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.queue_processor_zip.output_base64sha256
  memory_size      = 256
  timeout          = 300

  environment {
    variables = {
      STEP_FUNCTION_ARN = var.step_function_arn
      DLQ_URL          = var.dlq_url
      LOG_LEVEL        = "INFO"
    }
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-queue-processor"
      Environment = var.environment
      Purpose     = "queue-processing"
    }
  )
}

# ==========================================
# SQS Lambda Event Source Mapping
# ==========================================
resource "aws_lambda_event_source_mapping" "sqs_to_lambda" {
  event_source_arn = var.main_queue_arn
  function_name    = aws_lambda_function.queue_processor.arn
  batch_size       = 10
  maximum_batching_window_in_seconds = 5
  
  depends_on = [aws_lambda_function.queue_processor]
}

# ==========================================
# CloudWatch Log Group
# ==========================================
resource "aws_cloudwatch_log_group" "queue_processor_logs" {
  name              = "/aws/lambda/${aws_lambda_function.queue_processor.function_name}"
  retention_in_days = 30

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-queue-processor-logs"
      Environment = var.environment
    }
  )
}
