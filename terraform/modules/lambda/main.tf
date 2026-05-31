data "archive_file" "src" {
  type        = "zip"
  source_dir  = "${path.root}/../src"
  output_path = "${path.module}/lambda_src.zip"
}

resource "aws_lambda_function" "this" {
  function_name    = var.function_name
  role             = var.role_arn
  runtime          = "python3.12"
  handler          = var.handler
  filename         = data.archive_file.src.output_path
  source_code_hash = data.archive_file.src.output_base64sha256
  timeout          = 30
  memory_size      = 128

  environment {
    variables = {
      AUDIT_TABLE_NAME = var.audit_table_name
      SNS_TOPIC_ARN    = var.sns_topic_arn
    }
  }

  tags = var.tags
}
