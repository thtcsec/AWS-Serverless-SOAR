variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "main_queue_arn" {
  description = "ARN of the main SQS queue"
  type        = string
}

variable "dlq_arn" {
  description = "ARN of the dead letter queue"
  type        = string
}

variable "dlq_url" {
  description = "URL of the dead letter queue"
  type        = string
}

variable "step_function_arn" {
  description = "ARN of the Step Functions state machine"
  type        = string
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
