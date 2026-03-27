# Enterprise SOAR ECS Fargate Workers
# Container-based workers for intensive incident response tasks

# ==========================================
# ECR Repositories
# ==========================================
resource "aws_ecr_repository" "forensics_worker" {
  name                 = "${var.environment}-soar-forensics-worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-ecr-forensics-worker"
    }
  )
}

resource "aws_ecr_repository" "isolation_worker" {
  name                 = "${var.environment}-soar-isolation-worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-ecr-isolation-worker"
    }
  )
}

resource "aws_ecr_repository" "report_worker" {
  name                 = "${var.environment}-soar-report-worker"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-ecr-report-worker"
    }
  )
}

# ==========================================
# ECS Cluster
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
      Name = "${var.environment}-ecs-soar-workers"
    }
  )
}

resource "aws_ecs_cluster_capacity_providers" "soar_workers" {
  cluster_name = aws_ecs_cluster.soar_workers.name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider  = "FARGATE"
  }
}

# ==========================================
# CloudWatch Log Group
# ==========================================
resource "aws_cloudwatch_log_group" "ecs_workers" {
  name              = "/ecs/soar-workers/${var.environment}"
  retention_in_days = var.log_retention_days

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-ecs-workers-log-group"
    }
  )
}

# ==========================================
# Task Execution IAM Role
# ==========================================
resource "aws_iam_role" "ecs_task_execution_role" {
  name = "${var.environment}-soar-ecs-task-execution-role"

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
}

resource "aws_iam_role_policy" "ecs_task_execution_policy" {
  name = "${var.environment}-soar-ecs-task-execution-policy"
  role = aws_iam_role.ecs_task_execution_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ]
        Resource = [
          aws_ecr_repository.forensics_worker.arn,
          aws_ecr_repository.isolation_worker.arn,
          aws_ecr_repository.report_worker.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.ecs_workers.arn}:*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.worker_queue.arn
      }
    ]
  })
}

# ==========================================
# Task Role (for actual work)
# ==========================================
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
}

resource "aws_iam_role_policy" "ecs_task_policy" {
  name = "${var.environment}-soar-ecs-task-policy"
  role = aws_iam_role.ecs_task_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:CreateSnapshot",
          "ec2:CopySnapshot",
          "ec2:DescribeVolumes",
          "ec2:CreateVolume",
          "ec2:AttachVolume",
          "ec2:DescribeImages"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:ModifyInstanceAttribute",
          "ec2:TerminateInstances"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Purpose" = "soar-response"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = "*"
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
          "sns:Publish"
        ]
        Resource = aws_sns_topic.soar_alerts.arn
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters"
        ]
        Resource = "*"
      }
    ]
  })
}

# ==========================================
# Worker Queue (for ECS workers)
# ==========================================
resource "aws_sqs_queue" "worker_queue" {
  name                       = "${var.environment}-soar-worker-queue"
  visibility_timeout_seconds = 600
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 20

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.worker_dlq.arn
    maxReceiveCount     = 3
  })

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-worker-queue"
      Environment = var.environment
      Purpose     = "worker-processing"
    }
  )
}

resource "aws_sqs_queue" "worker_dlq" {
  name                      = "${var.environment}-soar-worker-dlq"
  visibility_timeout_seconds = 300
  message_retention_seconds = 1209600

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-worker-dlq"
      Environment = var.environment
      Purpose     = "worker-dead-letter"
    }
  )
}

# ==========================================
# Task Definitions
# ==========================================

# Forensics Worker Task Definition
resource "aws_ecs_task_definition" "forensics_worker" {
  family                   = "${var.environment}-soar-forensics-worker"
  network_mode             = "awsvpc"
  requires_compatibilities  = ["FARGATE"]
  cpu                      = "2048"
  memory                   = "4096"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "forensics-worker"
      image     = "${aws_ecr_repository.forensics_worker.repository_url}:latest"
      essential = true

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "LOG_LEVEL"
          value = "INFO"
        },
        {
          name  = "WORKER_QUEUE_URL"
          value = aws_sqs_queue.worker_queue.url
        },
        {
          name  = "DLQ_URL"
          value = aws_sqs_queue.worker_dlq.url
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_workers.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "forensics"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-forensics-task"
    }
  )
}

# Isolation Worker Task Definition
resource "aws_ecs_task_definition" "isolation_worker" {
  family                   = "${var.environment}-soar-isolation-worker"
  network_mode             = "awsvpc"
  requires_compatibilities  = ["FARGATE"]
  cpu                      = "1024"
  memory                   = "2048"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "isolation-worker"
      image     = "${aws_ecr_repository.isolation_worker.repository_url}:latest"
      essential = true

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "LOG_LEVEL"
          value = "INFO"
        },
        {
          name  = "WORKER_QUEUE_URL"
          value = aws_sqs_queue.worker_queue.url
        },
        {
          name  = "ISOLATION_SG_ID"
          value = aws_security_group.isolation_sg.id
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_workers.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "isolation"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-isolation-task"
    }
  )
}

# Report Worker Task Definition
resource "aws_ecs_task_definition" "report_worker" {
  family                   = "${var.environment}-soar-report-worker"
  network_mode             = "awsvpc"
  requires_compatibilities  = ["FARGATE"]
  cpu                      = "512"
  memory                   = "1024"
  execution_role_arn       = aws_iam_role.ecs_task_execution_role.arn
  task_role_arn            = aws_iam_role.ecs_task_role.arn

  container_definitions = jsonencode([
    {
      name      = "report-worker"
      image     = "${aws_ecr_repository.report_worker.repository_url}:latest"
      essential = true

      environment = [
        {
          name  = "ENVIRONMENT"
          value = var.environment
        },
        {
          name  = "LOG_LEVEL"
          value = "INFO"
        },
        {
          name  = "WORKER_QUEUE_URL"
          value = aws_sqs_queue.worker_queue.url
        },
        {
          name  = "REPORT_BUCKET"
          value = aws_s3_bucket.incident_reports.id
        }
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.ecs_workers.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "report"
        }
      }

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"]
        interval    = 30
        timeout     = 5
        retries     = 3
        startPeriod = 60
      }
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-report-task"
    }
  )
}

# ==========================================
# ECS Services
# ==========================================
resource "aws_ecs_service" "forensics_worker_service" {
  name            = "${var.environment}-soar-forensics-service"
  cluster         = aws_ecs_cluster.soar_workers.id
  task_definition = aws_ecs_task_definition.forensics_worker.arn
  desired_count   = var.forensics_worker_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.ecs_tasks_subnet.id]
    security_groups  = [aws_security_group.ecs_tasks_sg.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.forensics.arn
    container_name   = "forensics-worker"
    container_port   = 8080
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100
  health_check_grace_period_seconds  = 60

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-forensics-service"
    }
  )
}

resource "aws_ecs_service" "isolation_worker_service" {
  name            = "${var.environment}-soar-isolation-service"
  cluster         = aws_ecs_cluster.soar_workers.id
  task_definition = aws_ecs_task_definition.isolation_worker.arn
  desired_count   = var.isolation_worker_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.ecs_tasks_subnet.id]
    security_groups  = [aws_security_group.ecs_tasks_sg.id]
    assign_public_ip = false
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-isolation-service"
    }
  )
}

resource "aws_ecs_service" "report_worker_service" {
  name            = "${var.environment}-soar-report-service"
  cluster         = aws_ecs_cluster.soar_workers.id
  task_definition = aws_ecs_task_definition.report_worker.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = [aws_subnet.ecs_tasks_subnet.id]
    security_groups  = [aws_security_group.ecs_tasks_sg.id]
    assign_public_ip = false
  }

  deployment_controller {
    type = "ECS"
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_maximum_percent         = 200
  deployment_minimum_healthy_percent = 100

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-report-service"
    }
  )
}

# ==========================================
# Application Load Balancer
# ==========================================
resource "aws_lb" "workers_alb" {
  name               = "${var.environment}-soar-workers-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_subnet.id]

  enable_deletion_protection = false

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-workers-alb"
    }
  )
}

resource "aws_lb_target_group" "forensics" {
  name     = "${var.environment}-forensics-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.soar_vpc.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.environment}-forensics-tg"
  }
}

resource "aws_lb_listener" "forensics" {
  load_balancer_arn = aws_lb.workers_alb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.forensics.arn
  }
}

# ==========================================
# Networking for ECS
# ==========================================
resource "aws_subnet" "ecs_tasks_subnet" {
  vpc_id                  = aws_vpc.soar_vpc.id
  cidr_block              = var.ecs_subnet_cidr
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.environment}-ecs-tasks-subnet"
  }
}

resource "aws_security_group" "ecs_tasks_sg" {
  name        = "${var.environment}-soar-ecs-tasks-sg"
  description = "Security group for ECS Fargate tasks"
  vpc_id      = aws_vpc.soar_vpc.id

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-ecs-tasks-sg"
  }
}

resource "aws_security_group" "alb_sg" {
  name        = "${var.environment}-soar-alb-sg"
  description = "Security group for ALB"
  vpc_id      = aws_vpc.soar_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.environment}-alb-sg"
  }
}

# ==========================================
# S3 Bucket for Incident Reports
# ==========================================
resource "aws_s3_bucket" "incident_reports" {
  bucket = "${var.environment}-soar-incident-reports"

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-incident-reports"
    }
  )
}

resource "aws_s3_bucket_versioning" "incident_reports" {
  bucket = aws_s3_bucket.incident_reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "incident_reports" {
  bucket = aws_s3_bucket.incident_reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "incident_reports" {
  bucket = aws_s3_bucket.incident_reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ==========================================
# SNS Topic for Alerts
# ==========================================
resource "aws_sns_topic" "soar_alerts" {
  name = "${var.environment}-soar-alerts"

  tags = merge(
    var.tags,
    {
      Name = "${var.environment}-soar-alerts"
    }
  )
}
