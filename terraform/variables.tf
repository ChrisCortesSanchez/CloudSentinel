variable "aws_region" {
  type        = string
  description = "AWS region to deploy into"
  default     = "us-east-1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
  default     = "dev"
}

variable "notification_email" {
  type        = string
  description = "Email to receive SNS remediation alerts (optional)"
  default     = ""
}
