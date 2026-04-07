variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "ecs_subnet_cidr" {
  description = "CIDR block for ECS tasks subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
}

variable "forensics_worker_count" {
  description = "Number of forensics worker tasks"
  type        = number
  default     = 2
}

variable "isolation_worker_count" {
  description = "Number of isolation worker tasks"
  type        = number
  default     = 2
}

variable "alert_email" {
  description = "Email address for SNS alerts"
  type        = string
  default     = ""
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 3600
}

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SOAR"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}

variable "isolation_security_group_id" {
  description = "Security group ID for isolation workers"
  type        = string
}

variable "worker_security_group_id" {
  description = "Security group ID for worker tasks"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for worker tasks"
  type        = list(string)
}

variable "container_registry" {
  description = "ECR container registry URL"
  type        = string
}

variable "worker_desired_count" {
  description = "Desired number of worker tasks"
  type        = number
  default     = 1
}
