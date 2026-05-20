import json
import os
import boto3
import pytest
from freezegun import freeze_time
from moto import mock_aws

os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts")

from src.shared.notifier import Notifier

TOPIC_ARN = "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts"


@pytest.fixture()
def sns_topic():
    with mock_aws():
        client = boto3.client("sns", region_name="us-east-1")
        client.create_topic(Name="cloudsentinel-alerts")
        yield client


@freeze_time("2026-05-20T12:00:00Z")
def test_notify_publishes_to_sns(sns_topic):
    with mock_aws():
        notifier = Notifier(topic_arn=TOPIC_ARN)
        notifier.notify(
            playbook="s3_public_access",
            resource_arn="arn:aws:s3:::my-public-bucket",
            action_taken="blocked_public_access",
            finding_id="finding-abc-123",
        )

        sqs = boto3.client("sqs", region_name="us-east-1")
        queue = sqs.create_queue(QueueName="test-queue")
        queue_url = queue["QueueUrl"]
        queue_attrs = sqs.get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        queue_arn = queue_attrs["Attributes"]["QueueArn"]

        sns_client = boto3.client("sns", region_name="us-east-1")
        sns_client.subscribe(TopicArn=TOPIC_ARN, Protocol="sqs", Endpoint=queue_arn)

        notifier.notify(
            playbook="s3_public_access",
            resource_arn="arn:aws:s3:::my-public-bucket",
            action_taken="blocked_public_access",
            finding_id="finding-abc-123",
        )

        messages = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1)
        assert "Messages" in messages
        body = json.loads(messages["Messages"][0]["Body"])
        message_text = body["Message"]

        assert "s3_public_access" in message_text
        assert "arn:aws:s3:::my-public-bucket" in message_text
        assert "blocked_public_access" in message_text
        assert "finding-abc-123" in message_text
        assert "2026-05-20" in message_text


def test_notify_raises_on_missing_topic_arn():
    with mock_aws():
        with pytest.raises(ValueError, match="topic_arn"):
            Notifier(topic_arn="")


def test_notify_raises_on_missing_resource_arn():
    with mock_aws():
        notifier = Notifier(topic_arn=TOPIC_ARN)
        with pytest.raises(ValueError, match="resource_arn"):
            notifier.notify(
                playbook="s3_public_access",
                resource_arn="",
                action_taken="blocked_public_access",
                finding_id="finding-abc-123",
            )


def test_notify_raises_on_missing_finding_id():
    with mock_aws():
        notifier = Notifier(topic_arn=TOPIC_ARN)
        with pytest.raises(ValueError, match="finding_id"):
            notifier.notify(
                playbook="s3_public_access",
                resource_arn="arn:aws:s3:::bucket",
                action_taken="blocked_public_access",
                finding_id="",
            )
