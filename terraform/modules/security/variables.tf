variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "soar_account_id" {
  description = "AWS account ID where SOAR is deployed"
  type        = string
}

variable "soar_region" {
  description = "AWS region where SOAR is deployed"
  type        = string
  default     = "us-east-1"
}

variable "soar_sns_topic" {
  description = "SNS topic name in SOAR account for event forwarding"
  type        = string
  default     = "soar-security-alerts"
}

variable "external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = ""
}

variable "vpc_id" {
  description = "VPC ID where the responder security group will be created"
  type        = string
  default     = ""
}

variable "allowed_vpcs" {
  description = "List of VPC IDs where SOAR can take actions"
  type        = list(string)
  default     = []
}

variable "allowed_iam_users" {
  description = "List of IAM user names SOAR can modify"
  type        = list(string)
  default     = ["*"]
}

variable "allowed_buckets" {
  description = "List of S3 bucket names SOAR can access"
  type        = list(string)
  default     = []
}

variable "enable_event_forwarding" {
  description = "Enable CloudWatch event forwarding to SOAR account"
  type        = bool
  default     = false
}

variable "enable_config_recording" {
  description = "Enable AWS Config recording for compliance"
  type        = bool
  default     = false
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
