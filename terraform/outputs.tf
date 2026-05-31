output "audit_table_name" {
  description = "DynamoDB audit table name"
  value       = module.dynamodb.table_name
}

output "sns_topic_arn" {
  description = "SNS alerts topic ARN"
  value       = module.sns.topic_arn
}

output "lambda_s3_function_name" {
  description = "S3 remediation Lambda function name"
  value       = module.lambda_s3.function_name
}

output "eventbridge_s3_rule_arn" {
  description = "EventBridge rule ARN for S3 findings"
  value       = module.eventbridge_s3.rule_arn
}
