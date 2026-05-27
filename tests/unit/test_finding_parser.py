import pytest

from src.shared.finding_parser import FindingParser

VALID_EVENT = {
    "version": "0",
    "id": "event-id-001",
    "source": "aws.securityhub",
    "detail-type": "Security Hub Findings - Imported",
    "detail": {
        "findings": [
            {
                "Id": "arn:aws:securityhub:us-east-1:123456789012:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.2/finding/finding-abc-123",
                "Resources": [
                    {
                        "Type": "AwsS3Bucket",
                        "Id": "arn:aws:s3:::my-public-bucket",
                    }
                ],
            }
        ]
    },
}


def test_parse_returns_finding_id():
    result = FindingParser.parse(VALID_EVENT)
    assert result["finding_id"] == (
        "arn:aws:securityhub:us-east-1:123456789012:subscription/"
        "aws-foundational-security-best-practices/v/1.0.0/S3.2/finding/finding-abc-123"
    )


def test_parse_returns_resource_arn():
    result = FindingParser.parse(VALID_EVENT)
    assert result["resource_arn"] == "arn:aws:s3:::my-public-bucket"


def test_parse_returns_resource_type():
    result = FindingParser.parse(VALID_EVENT)
    assert result["resource_type"] == "AwsS3Bucket"


def test_parse_raises_on_missing_findings():
    event = {"detail": {}}
    with pytest.raises(ValueError, match="findings"):
        FindingParser.parse(event)


def test_parse_raises_on_empty_findings():
    event = {"detail": {"findings": []}}
    with pytest.raises(ValueError, match="findings"):
        FindingParser.parse(event)


def test_parse_raises_on_missing_resources():
    event = {
        "detail": {
            "findings": [
                {
                    "Id": "finding-xyz",
                    "Resources": [],
                }
            ]
        }
    }
    with pytest.raises(ValueError, match="resources"):
        FindingParser.parse(event)


def test_parse_raises_on_missing_detail():
    with pytest.raises(ValueError, match="findings"):
        FindingParser.parse({})
