# Enterprise SOAR Module
# Workflow Engine, Message Queues, and Container Workers

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
# Message Queue Layer (SQS)
# ==========================================
resource "aws_sqs_queue" "main_queue" {
  name                      = "${var.environment}-soar-events"
  max_receive_count         = 3
  visibility_timeout_seconds = 300
  message_retention_seconds = 1209600 # 14 days

  # Dead Letter Queue configuration
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dlq.arn
    maxReceiveCount     = 5
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-main-queue"
      Environment = var.environment
      Purpose     = "event-processing"
    }
  )
}

resource "aws_sqs_queue" "dlq" {
  name                      = "${var.environment}-soar-events-dlq"
  visibility_timeout_seconds = 300
  message_retention_seconds = 1209600 # 14 days

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-dlq"
      Environment = var.environment
      Purpose     = "dead-letter-queue"
    }
  )
}

# ==========================================
# Workflow Engine (Step Functions)
# ==========================================
resource "aws_iam_role" "step_function_role" {
  name = "${var.environment}-soar-step-function-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
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
      Name        = "${var.environment}-soar-sfn-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_policy" "step_function_policy" {
  name = "${var.environment}-soar-step-function-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "ecs:RunTask",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "step_function_policy_attach" {
  role       = aws_iam_role.step_function_role.name
  policy_arn = aws_iam_policy.step_function_policy.arn
}

resource "aws_sfn_state_machine" "incident_response" {
  name     = "${var.environment}-soar-incident-response"
  role_arn = aws_iam_role.step_function_role.arn

  definition = jsonencode({
    StartAt = "DetectSeverity"
    States = {
      DetectSeverity = {
        Type = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.environment}-soar-detect-severity"
        Next = "IsolateInstance"
        Retry = [{
          ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts = 2
          BackoffRate = 2.0
        }]
      }
      IsolateInstance = {
        Type = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.environment}-soar-isolate-instance"
        Next = "CreateSnapshot"
        Retry = [{
          ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts = 2
          BackoffRate = 2.0
        }]
      }
      CreateSnapshot = {
        Type = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.environment}-soar-create-snapshot"
        Next = "HumanApproval"
        Retry = [{
          ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts = 2
          BackoffRate = 2.0
        }]
      }
      HumanApproval = {
        Type = "Wait"
        Seconds = var.approval_wait_time
        Next = "TerminateInstance"
      }
      TerminateInstance = {
        Type = "Task"
        Resource = "arn:aws:lambda:${var.aws_region}:${data.aws_caller_identity.current.account_id}:function:${var.environment}-soar-terminate-instance"
        End = true
        Retry = [{
          ErrorEquals = ["Lambda.ServiceException", "Lambda.AWSLambdaException", "Lambda.SdkClientException", "Lambda.TooManyRequestsException"]
          IntervalSeconds = 2
          MaxAttempts = 2
          BackoffRate = 2.0
        }]
      }
    }
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-incident-response"
      Environment = var.environment
      Purpose     = "workflow-engine"
    }
  )
}

# ==========================================
# Container Workers (ECS Fargate)
# ==========================================
resource "aws_ecs_cluster" "soar_workers" {
  name = "${var.environment}-soar-workers"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-workers-cluster"
      Environment = var.environment
      Purpose     = "worker-containers"
    }
  )
}

resource "aws_ecs_task_definition" "isolation_worker" {
  family                   = "${var.environment}-soar-isolation-worker"
  network_mode            = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                     = "256"
  memory                  = "512"
  execution_role_arn       = aws_iam_role.ecs_execution_role.arn
  task_role_arn           = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name  = "isolation-worker"
      image = "${var.container_registry}/soar-isolation-worker:latest"
      
      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "ISOLATION_SG_ID"
          value = var.isolation_security_group_id
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/${var.environment}-soar-isolation-worker"
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "ecs"
        }
      }

      portMappings = [
        {
          containerPort = 8080
          protocol      = "tcp"
        }
      ]
    }
  ])

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-isolation-worker"
      Environment = var.environment
    }
  )
}

resource "aws_ecs_service" "isolation_worker" {
  name            = "${var.environment}-soar-isolation-worker"
  cluster         = aws_ecs_cluster.soar_workers.id
  task_definition = aws_ecs_task_definition.isolation_worker.arn
  desired_count   = var.worker_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [var.worker_security_group_id]
    assign_public_ip = false
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-isolation-worker-service"
      Environment = var.environment
    }
  )
}

# ==========================================
# ECS IAM Roles
# ==========================================
resource "aws_iam_role" "ecs_execution_role" {
  name = "${var.environment}-soar-ecs-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-ecs-execution-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_role_policy_attachment" "ecs_execution_role_policy" {
  role       = aws_iam_role.ecs_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role" "ecs_task_role" {
  name = "${var.environment}-soar-ecs-task-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
      }
    ]
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-ecs-task-role"
      Environment = var.environment
    }
  )
}

resource "aws_iam_policy" "ecs_task_policy" {
  name = "${var.environment}-soar-ecs-task-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:ModifyInstanceAttribute",
          "ec2:CreateSnapshot",
          "ec2:DeleteSnapshot",
          "ec2:TerminateInstances",
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "ecs_task_policy_attach" {
  role       = aws_iam_role.ecs_task_role.name
  policy_arn = aws_iam_policy.ecs_task_policy.arn
}

# ==========================================
# CloudWatch Log Groups
# ==========================================
resource "aws_cloudwatch_log_group" "ecs_logs" {
  name              = "/ecs/${var.environment}-soar-isolation-worker"
  retention_in_days = 30

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-ecs-logs"
      Environment = var.environment
    }
  )
}

# Data source for current account
data "aws_caller_identity" "current" {}
