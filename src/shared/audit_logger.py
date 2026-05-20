import os
from datetime import datetime, timezone

import boto3


class AuditLogger:
    def __init__(self, table_name: str | None = None):
        self._table_name = table_name or os.environ["AUDIT_TABLE_NAME"]
        self._table = boto3.resource("dynamodb").Table(self._table_name)

    def log(
        self,
        finding_id: str,
        resource_arn: str,
        playbook: str,
        action_taken: str,
    ) -> None:
        if not finding_id:
            raise ValueError("finding_id must not be empty")
        if not resource_arn:
            raise ValueError("resource_arn must not be empty")

        self._table.put_item(
            Item={
                "finding_id": finding_id,
                "timestamp": datetime.now(tz=timezone.utc).isoformat(),
                "resource_arn": resource_arn,
                "playbook": playbook,
                "action_taken": action_taken,
            }
        )
