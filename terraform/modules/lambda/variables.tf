variable "function_name" {
  type        = string
  description = "Lambda function name"
}

variable "handler" {
  type        = string
  description = "Lambda handler in module.function format"
}

variable "role_arn" {
  type        = string
  description = "IAM role ARN for Lambda execution"
}

variable "audit_table_name" {
  type        = string
  description = "DynamoDB table name passed as env var"
}

variable "sns_topic_arn" {
  type        = string
  description = "SNS topic ARN passed as env var"
}

variable "tags" {
  type    = map(string)
  default = {}
}
