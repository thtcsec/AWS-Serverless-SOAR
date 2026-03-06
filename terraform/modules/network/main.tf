# Enterprise SOAR Network Module
# Provides VPC, subnets, security groups for enterprise deployment

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
# VPC Configuration
# ==========================================
resource "aws_vpc" "soar_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-vpc"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  )
}

# ==========================================
# Internet Gateway
# ==========================================
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.soar_vpc.id

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-igw"
      Environment = var.environment
    }
  )
}

# ==========================================
# Public Subnets
# ==========================================
resource "aws_subnet" "public_subnets" {
  count = length(var.public_subnet_cidrs)

  vpc_id                  = aws_vpc.soar_vpc.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-public-subnet-${count.index + 1}"
      Environment = var.environment
      Type        = "public"
      AZ          = var.availability_zones[count.index]
    }
  )
}

# ==========================================
# Private Subnets
# ==========================================
resource "aws_subnet" "private_subnets" {
  count = length(var.private_subnet_cidrs)

  vpc_id            = aws_vpc.soar_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-private-subnet-${count.index + 1}"
      Environment = var.environment
      Type        = "private"
      AZ          = var.availability_zones[count.index]
    }
  )
}

# ==========================================
# NAT Gateway for Private Subnets
# ==========================================
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? 1 : 0
  domain = "vpc"

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-nat-eip"
      Environment = var.environment
    }
  )

  depends_on = [aws_internet_gateway.igw]
}

resource "aws_nat_gateway" "nat" {
  count         = var.enable_nat_gateway ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public_subnets[0].id

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-nat-gw"
      Environment = var.environment
    }
  )

  depends_on = [aws_internet_gateway.igw]
}

# ==========================================
# Route Tables
# ==========================================
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.soar_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-public-rt"
      Environment = var.environment
    }
  )
}

resource "aws_route_table" "private" {
  count = var.enable_nat_gateway ? 1 : 0
  vpc_id = aws_vpc.soar_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat[0].id
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-private-rt"
      Environment = var.environment
    }
  )
}

resource "aws_route_table_association" "public" {
  count = length(var.public_subnet_cidrs)

  subnet_id      = aws_subnet.public_subnets[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = var.enable_nat_gateway ? length(var.private_subnet_cidrs) : 0

  subnet_id      = aws_subnet.private_subnets[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# ==========================================
# Security Groups
# ==========================================
resource "aws_security_group" "isolation_sg" {
  name        = "${var.environment}-soar-isolation-sg"
  description = "Zero ingress/egress security group for incident isolation"
  vpc_id      = aws_vpc.soar_vpc.id

  # No ingress or egress rules - blocks all traffic

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-isolation-sg"
      Environment = var.environment
      Purpose     = "incident-isolation"
    }
  )
}

resource "aws_security_group" "worker_sg" {
  name        = "${var.environment}-soar-worker-sg"
  description = "Security group for SOAR container workers"
  vpc_id      = aws_vpc.soar_vpc.id

  ingress {
    description = "Allow traffic from VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-worker-sg"
      Environment = var.environment
      Purpose     = "worker-containers"
    }
  )
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "${var.environment}-soar-vulnerable-sg"
  description = "Intentionally permissive SG for testing detection"
  vpc_id      = aws_vpc.soar_vpc.id

  ingress {
    description = "Allow all inbound traffic for testing"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-vulnerable-sg"
      Environment = var.environment
      Purpose     = "testing-detection"
    }
  )
}

# ==========================================
# VPC Flow Logs
# ==========================================
resource "aws_flow_log" "vpc_flow_log" {
  vpc_id               = aws_vpc.soar_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.vpc_flow_logs.arn
  iam_role_arn         = aws_iam_role.vpc_flow_log_role.arn

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-vpc-flow-log"
      Environment = var.environment
      Purpose     = "network-monitoring"
    }
  )
}

resource "aws_cloudwatch_log_group" "vpc_flow_logs" {
  name              = "/aws/vpc-flow-logs/${var.environment}-soar"
  retention_in_days = 90

  tags = merge(
    var.tags,
    {
      Name        = "${var.environment}-soar-vpc-flow-logs"
      Environment = var.environment
    }
  )
}

resource "aws_iam_role" "vpc_flow_log_role" {
  name = "${var.environment}-soar-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })

  tags = merge(var.tags, { Name = "${var.environment}-soar-flow-log-role" })
}

resource "aws_iam_role_policy" "vpc_flow_log_policy" {
  name = "${var.environment}-soar-vpc-flow-log-policy"
  role = aws_iam_role.vpc_flow_log_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }]
  })
}
