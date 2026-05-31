import boto3

from src.shared.audit_logger import AuditLogger
from src.shared.finding_parser import FindingParser
from src.shared.notifier import Notifier

_ec2 = boto3.client("ec2")
_audit = AuditLogger()
_notifier = Notifier()

_BLOCKED_PORTS = {22, 3389}
_OPEN_CIDR = "0.0.0.0/0"


def handler(event: dict, context) -> None:
    finding = FindingParser.parse(event)

    if finding["resource_type"] != "AwsEc2SecurityGroup":
        raise ValueError(f"Expected AwsEc2SecurityGroup, got {finding['resource_type']}")

    sg_id = finding["resource_arn"].split("/")[-1]

    rules_to_revoke = _find_open_ingress_rules(sg_id)
    if rules_to_revoke:
        _ec2.revoke_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=rules_to_revoke,
        )

    _audit.log(
        finding_id=finding["finding_id"],
        resource_arn=finding["resource_arn"],
        playbook="ec2_sg_lockdown",
        action_taken="revoked_open_ingress",
    )

    _notifier.notify(
        playbook="ec2_sg_lockdown",
        resource_arn=finding["resource_arn"],
        action_taken="revoked_open_ingress",
        finding_id=finding["finding_id"],
    )


def _find_open_ingress_rules(sg_id: str) -> list:
    sg = _ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    to_revoke = []
    for rule in sg["IpPermissions"]:
        if rule.get("FromPort") not in _BLOCKED_PORTS:
            continue
        open_ranges = [r for r in rule.get("IpRanges", []) if r["CidrIp"] == _OPEN_CIDR]
        if open_ranges:
            to_revoke.append({
                "IpProtocol": rule["IpProtocol"],
                "FromPort": rule["FromPort"],
                "ToPort": rule["ToPort"],
                "IpRanges": open_ranges,
            })
    return to_revoke
