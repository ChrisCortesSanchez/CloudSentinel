import os
import boto3
import pytest
from freezegun import freeze_time
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AUDIT_TABLE_NAME", "cloudsentinel-audit")

from src.shared.audit_logger import AuditLogger

TABLE_NAME = "cloudsentinel-audit"


@pytest.fixture()
def dynamodb_table():
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield boto3.resource("dynamodb", region_name="us-east-1").Table(TABLE_NAME)


@freeze_time("2026-05-20T12:00:00Z")
def test_log_remediation_writes_expected_item(dynamodb_table):
    with mock_aws():
        logger = AuditLogger(table_name=TABLE_NAME)
        logger.log(
            finding_id="finding-abc-123",
            resource_arn="arn:aws:s3:::my-public-bucket",
            playbook="s3_public_access",
            action_taken="blocked_public_access",
        )

        item = dynamodb_table.get_item(Key={"finding_id": "finding-abc-123"})["Item"]
        assert item["finding_id"] == "finding-abc-123"
        assert item["resource_arn"] == "arn:aws:s3:::my-public-bucket"
        assert item["playbook"] == "s3_public_access"
        assert item["action_taken"] == "blocked_public_access"
        assert item["timestamp"] == "2026-05-20T12:00:00+00:00"


@freeze_time("2026-05-20T12:00:00Z")
def test_log_remediation_multiple_findings(dynamodb_table):
    with mock_aws():
        logger = AuditLogger(table_name=TABLE_NAME)
        for i in range(3):
            logger.log(
                finding_id=f"finding-{i}",
                resource_arn=f"arn:aws:s3:::bucket-{i}",
                playbook="s3_public_access",
                action_taken="blocked_public_access",
            )

        for i in range(3):
            item = dynamodb_table.get_item(Key={"finding_id": f"finding-{i}"})["Item"]
            assert item["resource_arn"] == f"arn:aws:s3:::bucket-{i}"


def test_log_raises_on_missing_finding_id(dynamodb_table):
    with mock_aws():
        logger = AuditLogger(table_name=TABLE_NAME)
        with pytest.raises(ValueError, match="finding_id"):
            logger.log(
                finding_id="",
                resource_arn="arn:aws:s3:::bucket",
                playbook="s3_public_access",
                action_taken="blocked_public_access",
            )


def test_log_raises_on_missing_resource_arn(dynamodb_table):
    with mock_aws():
        logger = AuditLogger(table_name=TABLE_NAME)
        with pytest.raises(ValueError, match="resource_arn"):
            logger.log(
                finding_id="finding-xyz",
                resource_arn="",
                playbook="s3_public_access",
                action_taken="blocked_public_access",
            )
