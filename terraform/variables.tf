variable "aws_region" {
  description = "The AWS region to deploy resources in"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address to receive GuardDuty SOAR alerts"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the project VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for the public subnet (where the target EC2 lives)"
  type        = string
  default     = "10.0.1.0/24"
}

variable "lambda_memory_size" {
  description = "Lambda memory size in MB for SOAR functions"
  type        = number
  default     = 256
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds for SOAR functions"
  type        = number
  default     = 60
}

variable "lambda_reserved_concurrency" {
  description = "Reserved concurrency for SOAR functions. Null keeps AWS default"
  type        = number
  default     = null
}

variable "sns_alert_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications"
  type        = string
  default     = ""
}
