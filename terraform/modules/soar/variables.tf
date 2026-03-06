variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "isolation_security_group_id" {
  description = "ID of the isolation security group"
  type        = string
}

variable "worker_security_group_id" {
  description = "ID of the worker security group"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs for ECS tasks"
  type        = list(string)
}

variable "container_registry" {
  description = "Container registry URL"
  type        = string
  default     = "123456789012.dkr.ecr.us-east-1.amazonaws.com"
}

variable "worker_desired_count" {
  description = "Desired count of worker containers"
  type        = number
  default     = 2
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 3600 # 1 hour
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
