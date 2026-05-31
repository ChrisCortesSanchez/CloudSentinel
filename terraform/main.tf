terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Project     = "CloudSentinel"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

module "dynamodb" {
  source     = "./modules/dynamodb"
  table_name = "cloudsentinel-audit-${var.environment}"
  tags       = local.common_tags
}

module "sns" {
  source             = "./modules/sns"
  topic_name         = "cloudsentinel-alerts-${var.environment}"
  notification_email = var.notification_email
  tags               = local.common_tags
}

module "iam" {
  source             = "./modules/iam"
  role_name          = "cloudsentinel-lambda-${var.environment}"
  dynamodb_table_arn = module.dynamodb.table_arn
  sns_topic_arn      = module.sns.topic_arn
  tags               = local.common_tags
}

module "lambda_s3" {
  source           = "./modules/lambda"
  function_name    = "cloudsentinel-s3-remediation-${var.environment}"
  handler          = "handlers.s3_remediation.handler"
  role_arn         = module.iam.role_arn
  audit_table_name = module.dynamodb.table_name
  sns_topic_arn    = module.sns.topic_arn
  tags             = local.common_tags
}

module "eventbridge_s3" {
  source               = "./modules/eventbridge"
  rule_name            = "cloudsentinel-s3-public-access-${var.environment}"
  description          = "Triggers S3 remediation on Security Hub AwsS3Bucket findings"
  lambda_arn           = module.lambda_s3.function_arn
  lambda_function_name = module.lambda_s3.function_name
  tags                 = local.common_tags

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Resources = {
          Type = ["AwsS3Bucket"]
        }
        Compliance = {
          Status = ["FAILED"]
        }
      }
    }
  })
}
