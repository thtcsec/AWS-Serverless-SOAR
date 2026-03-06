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
