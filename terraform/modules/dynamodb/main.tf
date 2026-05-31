resource "aws_dynamodb_table" "audit" {
  name         = var.table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  tags = var.tags
}
