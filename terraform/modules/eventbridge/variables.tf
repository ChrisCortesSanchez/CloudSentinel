variable "rule_name" {
  type        = string
  description = "EventBridge rule name"
}

variable "description" {
  type        = string
  description = "EventBridge rule description"
  default     = ""
}

variable "event_pattern" {
  type        = string
  description = "JSON event pattern for the rule"
}

variable "lambda_arn" {
  type        = string
  description = "ARN of the Lambda function to invoke"
}

variable "lambda_function_name" {
  type        = string
  description = "Name of the Lambda function (for permission resource)"
}

variable "tags" {
  type    = map(string)
  default = {}
}
