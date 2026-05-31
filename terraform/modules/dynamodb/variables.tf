variable "table_name" {
  type        = string
  description = "DynamoDB table name for remediation audit logs"
}

variable "tags" {
  type    = map(string)
  default = {}
}
