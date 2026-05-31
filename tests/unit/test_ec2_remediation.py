import os
import boto3
import pytest
from moto import mock_aws

os.environ.setdefault("AUDIT_TABLE_NAME", "cloudsentinel-audit")
os.environ.setdefault("SNS_TOPIC_ARN", "arn:aws:sns:us-east-1:123456789012:cloudsentinel-alerts")

from src.handlers.ec2_remediation import handler

SG_ID = "sg-12345678"
ACCOUNT_ID = "123456789012"

VALID_EVENT = {
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "findings": [
            {
                "Id": f"arn:aws:securityhub:us-east-1:{ACCOUNT_ID}:finding/finding-ec2-001",
                "Resources": [
                    {
                        "Type": "AwsEc2SecurityGroup",
                        "Id": f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:security-group/{SG_ID}",
                    }
                ],
            }
        ]
    },
}


@pytest.fixture()
def aws_resources():
    with mock_aws():
        ec2 = boto3.client("ec2", region_name="us-east-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-sg",
            Description="Test security group",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        )

        dynamodb = boto3.client("dynamodb", region_name="us-east-1")
        dynamodb.create_table(
            TableName="cloudsentinel-audit",
            KeySchema=[{"AttributeName": "finding_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "finding_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        boto3.client("sns", region_name="us-east-1").create_topic(
            Name="cloudsentinel-alerts"
        )

        yield {"ec2": ec2, "sg_id": sg_id}


def test_handler_revokes_ssh_rule(aws_resources):
    with mock_aws():
        event = _event_for_sg(aws_resources["sg_id"])
        handler(event, {})

        rules = _get_ingress_rules(aws_resources["ec2"], aws_resources["sg_id"])
        ports = {r["FromPort"] for r in rules}
        assert 22 not in ports


def test_handler_revokes_rdp_rule(aws_resources):
    with mock_aws():
        event = _event_for_sg(aws_resources["sg_id"])
        handler(event, {})

        rules = _get_ingress_rules(aws_resources["ec2"], aws_resources["sg_id"])
        ports = {r["FromPort"] for r in rules}
        assert 3389 not in ports


def test_handler_preserves_non_flagged_rules(aws_resources):
    with mock_aws():
        event = _event_for_sg(aws_resources["sg_id"])
        handler(event, {})

        rules = _get_ingress_rules(aws_resources["ec2"], aws_resources["sg_id"])
        ports = {r["FromPort"] for r in rules}
        assert 443 in ports


def test_handler_writes_audit_log(aws_resources):
    with mock_aws():
        event = _event_for_sg(aws_resources["sg_id"])
        handler(event, {})

        table = boto3.resource("dynamodb", region_name="us-east-1").Table("cloudsentinel-audit")
        item = table.get_item(
            Key={"finding_id": f"arn:aws:securityhub:us-east-1:{ACCOUNT_ID}:finding/finding-ec2-001"}
        )["Item"]

        assert item["playbook"] == "ec2_sg_lockdown"
        assert item["action_taken"] == "revoked_open_ingress"


def test_handler_publishes_sns_notification(aws_resources):
    with mock_aws():
        from unittest.mock import patch

        event = _event_for_sg(aws_resources["sg_id"])
        with patch("src.handlers.ec2_remediation._notifier") as mock_notifier:
            handler(event, {})
            mock_notifier.notify.assert_called_once_with(
                playbook="ec2_sg_lockdown",
                resource_arn=f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:security-group/{aws_resources['sg_id']}",
                action_taken="revoked_open_ingress",
                finding_id=f"arn:aws:securityhub:us-east-1:{ACCOUNT_ID}:finding/finding-ec2-001",
            )


def test_handler_raises_on_non_ec2_resource(aws_resources):
    with mock_aws():
        event = {
            "detail": {
                "findings": [
                    {
                        "Id": "finding-s3-001",
                        "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::bucket"}],
                    }
                ]
            }
        }
        with pytest.raises(ValueError, match="AwsEc2SecurityGroup"):
            handler(event, {})


def test_handler_noop_when_no_open_rules(aws_resources):
    with mock_aws():
        ec2 = aws_resources["ec2"]
        sg_id = aws_resources["sg_id"]

        # Revoke open rules manually first
        ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
            ],
        )

        event = _event_for_sg(sg_id)
        handler(event, {})  # should not raise

        rules = _get_ingress_rules(ec2, sg_id)
        ports = {r["FromPort"] for r in rules}
        assert 22 not in ports
        assert 3389 not in ports


# --- helpers ---

def _event_for_sg(sg_id: str) -> dict:
    return {
        "detail": {
            "findings": [
                {
                    "Id": f"arn:aws:securityhub:us-east-1:{ACCOUNT_ID}:finding/finding-ec2-001",
                    "Resources": [
                        {
                            "Type": "AwsEc2SecurityGroup",
                            "Id": f"arn:aws:ec2:us-east-1:{ACCOUNT_ID}:security-group/{sg_id}",
                        }
                    ],
                }
            ]
        }
    }


def _get_ingress_rules(ec2_client, sg_id: str) -> list:
    sgs = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"]
    return sgs[0]["IpPermissions"]
