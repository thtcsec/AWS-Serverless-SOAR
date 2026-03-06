variable "environment" {
  description = "Environment name"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.1.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets"
  type        = list(string)
  default     = ["10.1.1.0/24", "10.1.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.1.11.0/24", "10.1.12.0/24"]
}

variable "availability_zones" {
  description = "Availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
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
  default     = 1
}

variable "approval_wait_time" {
  description = "Wait time for human approval in seconds"
  type        = number
  default     = 300 # 5 minutes for dev
}

# Multi-account configuration
variable "enable_dev_account_access" {
  description = "Whether to enable dev account access"
  type        = bool
  default     = false
}

variable "enable_staging_account_access" {
  description = "Whether to enable staging account access"
  type        = bool
  default     = false
}

variable "enable_prod_account_access" {
  description = "Whether to enable production account access"
  type        = bool
  default     = false
}

variable "dev_account_id" {
  description = "AWS account ID for dev environment"
  type        = string
  default     = ""
}

variable "staging_account_id" {
  description = "AWS account ID for staging environment"
  type        = string
  default     = ""
}

variable "prod_account_id" {
  description = "AWS account ID for production environment"
  type        = string
  default     = ""
}

variable "dev_account_email" {
  description = "Email address for dev account GuardDuty invitation"
  type        = string
  default     = ""
}

variable "staging_account_email" {
  description = "Email address for staging account GuardDuty invitation"
  type        = string
  default     = ""
}

variable "prod_account_email" {
  description = "Email address for production account GuardDuty invitation"
  type        = string
  default     = ""
}

variable "cross_account_external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = "soar-cross-account-dev"
}

# Integration configuration
variable "enable_slack_integration" {
  description = "Whether to enable Slack integration"
  type        = bool
  default     = false
}

variable "enable_jira_integration" {
  description = "Whether to enable Jira integration"
  type        = bool
  default     = false
}

variable "enable_siem_integration" {
  description = "Whether to enable SIEM integration"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_url" {
  description = "Jira instance URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_username" {
  description = "Jira API username"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "siem_endpoint" {
  description = "SIEM API endpoint URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "siem_api_key" {
  description = "SIEM API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "tags" {
  description = "Common tags"
  type        = map(string)
  default = {
    Project     = "SOAR"
    ManagedBy   = "terraform"
    Environment = "development"
  }
}
