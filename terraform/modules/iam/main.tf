data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda_exec" {
  name               = var.role_name
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
  tags               = var.tags
}

# CloudWatch Logs — basic Lambda execution
resource "aws_iam_role_policy_attachment" "basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# DynamoDB — write audit records only
data "aws_iam_policy_document" "dynamodb_write" {
  statement {
    actions   = ["dynamodb:PutItem"]
    resources = [var.dynamodb_table_arn]
  }
}

resource "aws_iam_role_policy" "dynamodb_write" {
  name   = "${var.role_name}-dynamodb-write"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.dynamodb_write.json
}

# SNS — publish to alerts topic only
data "aws_iam_policy_document" "sns_publish" {
  statement {
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }
}

resource "aws_iam_role_policy" "sns_publish" {
  name   = "${var.role_name}-sns-publish"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.sns_publish.json
}

# S3 — block public access on any bucket (scope narrows at EventBridge filter)
data "aws_iam_policy_document" "s3_remediate" {
  statement {
    actions   = ["s3:PutBucketPublicAccessBlock"]
    resources = ["arn:aws:s3:::*"]
  }
}

resource "aws_iam_role_policy" "s3_remediate" {
  name   = "${var.role_name}-s3-remediate"
  role   = aws_iam_role.lambda_exec.id
  policy = data.aws_iam_policy_document.s3_remediate.json
}
