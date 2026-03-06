variable "environment" {
  description = "Environment name"
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "enable_nat_gateway" {
  description = "Whether to enable NAT gateway"
  type        = bool
  default     = true
}

variable "container_registry" {
  description = "Container registry URL"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
}

variable "worker_desired_count" {
  description = "Desired count of worker containers"
  type        = number
  default     = 3
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 3600 # 1 hour for prod
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default = {
    Project     = "SOAR"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}
