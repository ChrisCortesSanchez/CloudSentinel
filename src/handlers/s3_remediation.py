import boto3

from src.shared.audit_logger import AuditLogger
from src.shared.finding_parser import FindingParser
from src.shared.notifier import Notifier

_s3 = boto3.client("s3")
_audit = AuditLogger()
_notifier = Notifier()


def handler(event: dict, context) -> None:
    finding = FindingParser.parse(event)

    if finding["resource_type"] != "AwsS3Bucket":
        raise ValueError(f"Expected AwsS3Bucket, got {finding['resource_type']}")

    bucket_name = finding["resource_arn"].split(":::")[-1]

    _s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    _audit.log(
        finding_id=finding["finding_id"],
        resource_arn=finding["resource_arn"],
        playbook="s3_public_access",
        action_taken="blocked_public_access",
    )

    _notifier.notify(
        playbook="s3_public_access",
        resource_arn=finding["resource_arn"],
        action_taken="blocked_public_access",
        finding_id=finding["finding_id"],
    )
