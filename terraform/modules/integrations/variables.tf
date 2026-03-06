variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "enable_slack_integration" {
  description = "Whether to enable Slack integration"
  type        = bool
  default     = true
}

variable "enable_jira_integration" {
  description = "Whether to enable Jira integration"
  type        = bool
  default     = true
}

variable "enable_siem_integration" {
  description = "Whether to enable SIEM integration"
  type        = bool
  default     = true
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
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SOAR"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}
