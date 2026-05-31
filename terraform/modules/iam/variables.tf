variable "role_name" {
  type        = string
  description = "Name of the Lambda IAM execution role"
}

variable "dynamodb_table_arn" {
  type        = string
  description = "ARN of the DynamoDB audit table"
}

variable "sns_topic_arn" {
  type        = string
  description = "ARN of the SNS alerts topic"
}

variable "tags" {
  type    = map(string)
  default = {}
}
