variable "environment" {
  description = "Environment name (dev, staging, prod)"
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

variable "alert_emoji" {
  description = "Alert emoji for Slack notifications"
  type        = string
  default     = "🚨"
}

variable "use_secrets_manager" {
  description = "Use AWS Secrets Manager for credentials"
  type        = bool
  default     = false
}

variable "slack_enabled" {
  description = "Enable Slack integration"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL"
  type        = string
  default     = ""
}

variable "jira_enabled" {
  description = "Enable Jira integration"
  type        = bool
  default     = false
}

variable "jira_url" {
  description = "Jira instance URL"
  type        = string
  default     = ""
}

variable "jira_username" {
  description = "Jira username"
  type        = string
  default     = ""
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_project_key" {
  description = "Jira project key"
  type        = string
  default     = "SEC"
}

variable "splunk_enabled" {
  description = "Enable Splunk integration"
  type        = bool
  default     = false
}

variable "splunk_hec_url" {
  description = "Splunk HTTP Event Collector URL"
  type        = string
  default     = ""
}

variable "splunk_hec_token" {
  description = "Splunk HEC token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "splunk_index" {
  description = "Splunk index name"
  type        = string
  default     = "aws-soar"
}

variable "pagerduty_enabled" {
  description = "Enable PagerDuty integration"
  type        = bool
  default     = false
}

variable "pagerduty_routing_key" {
  description = "PagerDuty routing key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "pagerduty_service_id" {
  description = "PagerDuty service ID"
  type        = string
  default     = ""
}

variable "teams_enabled" {
  description = "Enable Microsoft Teams integration"
  type        = bool
  default     = false
}

variable "teams_webhook_url" {
  description = "Microsoft Teams webhook URL"
  type        = string
  default     = ""
}

variable "threat_intel_enabled" {
  description = "Enable threat intelligence enrichment"
  type        = bool
  default     = false
}

variable "virustotal_api_key" {
  description = "VirusTotal API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "abuseipdb_api_key" {
  description = "AbuseIPDB API key"
  type        = string
  default     = ""
  sensitive   = true
}
