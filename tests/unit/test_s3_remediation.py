import os
import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AUDIT_TABLE_NAME", "cloudsentinel-audit")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts")

from src.handlers.s3_remediation import handler

BUCKET_NAME = "my-public-bucket"

VALID_EVENT = {
    "version": "0",
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "findings": [
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:finding/finding-s3-001",
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": f"arn:aws:s3:::{BUCKET_NAME}",
                    }
                ],
            }
        ]
    },
}


@pytest.fixture()
def aws_resources():
    with mock_aws():
        s3 = boto3.client("s3", region_name="us-east-1")
        s3.create_bucket(Bucket=BUCKET_NAME)
        s3.delete_public_access_block(Bucket=BUCKET_NAME)

        dynamodb = boto3.client("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="cloudsentinel-audit",
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        sns = boto3.client("sns", region_name="us-east-1")
        sns.create_topic(Name="cloudsentinel-alerts")

        yield {"s3": s3, "dynamodb": dynamodb, "sns": sns}


def test_handler_blocks_public_access(aws_resources):
    with mock_aws():
        handler(VALID_EVENT, {})

        s3 = aws_resources["s3"]
        config = s3.get_public_access_block(Bucket=BUCKET_NAME)["PublicAccessBlockConfiguration"]
        assert config["BlockPublicAcls"] is True
        assert config["IgnorePublicAcls"] is True
        assert config["BlockPublicPolicy"] is True
        assert config["RestrictPublicBuckets"] is True


def test_handler_writes_audit_log(aws_resources):
    with mock_aws():
        handler(VALID_EVENT, {})

        table = boto3.resource("dynamodb", region_name="us-east-1").Table("cloudsentinel-audit")
        item = table.get_item(
            Key={"finding_id": "arn:aws:securityhub:us-east-1:123456789012:finding/finding-s3-001"}
        )["Item"]

        assert item["resource_arn"] == f"arn:aws:s3:::{BUCKET_NAME}"
        assert item["playbook"] == "s3_public_access"
        assert item["action_taken"] == "blocked_public_access"


def test_handler_publishes_sns_notification(aws_resources):
    with mock_aws():
        from unittest.mock import patch

        with patch("src.handlers.s3_remediation._notifier") as mock_notifier:
            handler(VALID_EVENT, {})

            mock_notifier.notify.assert_called_once_with(
                playbook="s3_public_access",
                resource_arn=f"arn:aws:s3:::{BUCKET_NAME}",
                action_taken="blocked_public_access",
                finding_id="arn:aws:securityhub:us-east-1:123456789012:finding/finding-s3-001",
            )


def test_handler_raises_on_non_s3_resource(aws_resources):
    with mock_aws():
        event = {
            "detail": {
                "findings": [
                    {
                        "Id": "finding-ec2-001",
                        "Resources": [{"Type": "AwsEc2Instance", "Id": "arn:aws:ec2:::instance/i-123"}],
                    }
                ]
            }
        }
        with pytest.raises(ValueError, match="AwsS3Bucket"):
            handler(event, {})
