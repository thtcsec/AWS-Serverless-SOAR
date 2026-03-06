variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "cross_account_external_id" {
  description = "External ID for cross-account role assumption"
  type        = string
  default     = "soar-cross-account-2024"
}

variable "enable_dev_account_access" {
  description = "Whether to enable dev account access"
  type        = bool
  default     = true
}

variable "enable_staging_account_access" {
  description = "Whether to enable staging account access"
  type        = bool
  default     = true
}

variable "enable_prod_account_access" {
  description = "Whether to enable production account access"
  type        = bool
  default     = true
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

variable "tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Project     = "SOAR"
    ManagedBy   = "terraform"
    Environment = "production"
  }
}
