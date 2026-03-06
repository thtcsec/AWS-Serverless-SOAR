data "aws_caller_identity" "current" {}

# ==========================================
# 1. NETWORKING (VPC, Subnet, SG)
# ==========================================
resource "aws_vpc" "soar_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true

  tags = {
    Name = "soar-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.soar_vpc.id

  tags = {
    Name = "soar-igw"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.soar_vpc.id
  cidr_block              = var.public_subnet_cidr
  map_public_ip_on_launch = true

  tags = {
    Name = "soar-public-subnet"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.soar_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "soar-public-rt"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Vulnerable SG: Allows all ingress for testing
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-sg-for-testing"
  description = "Intentionally permissive SG for testing GuardDuty"
  vpc_id      = aws_vpc.soar_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "soar-vulnerable-sg"
  }
}

# Isolation SG: Used by SOAR Lambda to immediately cut off network
resource "aws_security_group" "isolation_sg" {
  name        = "soar-isolation-sg"
  description = "Zero ingress/egress. Applied purely by Incident Response Lambda."
  vpc_id      = aws_vpc.soar_vpc.id

  # Explicitly empty ingress/egress drops ALL traffic

  tags = {
    Name = "soar-isolation-sg"
  }
}

# ==========================================
# 2. COMPUTE (Target EC2)
# ==========================================
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

resource "aws_instance" "target_ec2" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]

  tags = {
    Name = "SOAR-Target-Instance"
  }
}

# ==========================================
# 3. SECURITY (GuardDuty)
# ==========================================
resource "aws_guardduty_detector" "detector" {
  enable = true
}

# ==========================================
# 4. NOTIFICATION (SNS)
# ==========================================
resource "aws_sns_topic" "soar_alerts" {
  name = "soar-security-alerts"
}

resource "aws_sns_topic_subscription" "email_sub" {
  topic_arn = aws_sns_topic.soar_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# ==========================================
# 5. AUTOMATION (Lambda & EventBridge)
# ==========================================

# ZIP the python source
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/lambda_function.py"
  output_path = "${path.module}/soar_lambda.zip"
}

resource "aws_lambda_function" "soar_responder" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "soar-incident-responder"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      ISOLATION_SG_ID = aws_security_group.isolation_sg.id
      SNS_TOPIC_ARN   = aws_sns_topic.soar_alerts.arn
    }
  }

  tags = {
    Name = "SOAR-Respondent-Lambda"
  }
}

# EventBridge Rule to capture GuardDuty Findings
resource "aws_cloudwatch_event_rule" "guardduty_finding" {
  name        = "capture-guardduty-findings"
  description = "Capture specific EC2 GuardDuty findings to trigger SOAR"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      # You can filter specific findings. We'll capture everything related to an Instance
      resource = {
        resourceType = ["Instance"]
      }
    }
  })
}

# Point EventBridge Rule to Lambda
resource "aws_cloudwatch_event_target" "trigger_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_finding.name
  target_id = "TriggerSOARLambda"
  arn       = aws_lambda_function.soar_responder.arn
}

# Grant EventBridge permission to invoke the Lambda Function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.soar_responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_finding.arn
}

# ==========================================
# 6. AUTOMATION: IAM COMPROMISE (Lambda & EventBridge)
# ==========================================

data "archive_file" "iam_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/iam_compromise_response.py"
  output_path = "${path.module}/iam_soar_lambda.zip"
}

resource "aws_lambda_function" "iam_soar_responder" {
  filename         = data.archive_file.iam_lambda_zip.output_path
  function_name    = "iam-soar-incident-responder"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "iam_compromise_response.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.iam_lambda_zip.output_base64sha256
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.soar_alerts.arn
    }
  }

  tags = {
    Name = "IAM-SOAR-Respondent-Lambda"
  }
}

resource "aws_cloudwatch_event_rule" "iam_finding" {
  name        = "capture-iam-findings"
  description = "Capture IAM updates to trigger SOAR"

  event_pattern = jsonencode({
    source = ["aws.iam"]
  })
}

resource "aws_cloudwatch_event_target" "trigger_iam_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_finding.name
  target_id = "TriggerIAMSOARLambda"
  arn       = aws_lambda_function.iam_soar_responder.arn
}

resource "aws_lambda_permission" "allow_eventbridge_iam" {
  statement_id  = "AllowExecutionFromEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_soar_responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_finding.arn
}

# ==========================================
# 7. AUTOMATION: S3 EXFILTRATION (Lambda & EventBridge)
# ==========================================

data "archive_file" "s3_lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../src/s3_exfiltration_response.py"
  output_path = "${path.module}/s3_soar_lambda.zip"
}

resource "aws_lambda_function" "s3_soar_responder" {
  filename         = data.archive_file.s3_lambda_zip.output_path
  function_name    = "s3-soar-incident-responder"
  role             = aws_iam_role.lambda_exec_role.arn
  handler          = "s3_exfiltration_response.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.s3_lambda_zip.output_base64sha256
  memory_size      = var.lambda_memory_size
  timeout          = var.lambda_timeout
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.soar_alerts.arn
    }
  }

  tags = {
    Name = "S3-SOAR-Respondent-Lambda"
  }
}

resource "aws_cloudwatch_event_rule" "s3_finding" {
  name        = "capture-s3-findings"
  description = "Capture S3 read events for exfiltration SOAR"

  event_pattern = jsonencode({
    source = ["aws.s3"]
    detail = {
      eventName = ["GetObject", "ListObjects", "DownloadFile"]
    }
  })
}

resource "aws_cloudwatch_event_target" "trigger_s3_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_finding.name
  target_id = "TriggerS3SOARLambda"
  arn       = aws_lambda_function.s3_soar_responder.arn
}

resource "aws_lambda_permission" "allow_eventbridge_s3" {
  statement_id  = "AllowExecutionFromEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_soar_responder.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_finding.arn
}
