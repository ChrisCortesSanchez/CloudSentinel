variable "topic_name" {
  type        = string
  description = "SNS topic name for remediation alerts"
}

variable "notification_email" {
  type        = string
  description = "Email address to receive remediation alerts (optional)"
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
