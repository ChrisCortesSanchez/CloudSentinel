import os
from datetime import datetime, timezone

import boto3


class Notifier:
    def __init__(self, topic_arn: str | None = None):
        self._topic_arn = topic_arn if topic_arn is not None else os.environ.get("SNS_TOPIC_ARN", "")
        if not self._topic_arn:
            raise ValueError("topic_arn must not be empty")
        self._sns = boto3.client("sns")

    def notify(
        self,
        playbook: str,
        resource_arn: str,
        action_taken: str,
        finding_id: str,
    ) -> None:
        if not resource_arn:
            raise ValueError("resource_arn must not be empty")
        if not finding_id:
            raise ValueError("finding_id must not be empty")

        timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = (
            f"[CloudSentinel] Auto-remediation executed\n"
            f"  Playbook:    {playbook}\n"
            f"  Resource:    {resource_arn}\n"
            f"  Action:      {action_taken}\n"
            f"  Finding ID:  {finding_id}\n"
            f"  Time:        {timestamp}"
        )

        self._sns.publish(
            TopicArn=self._topic_arn,
            Subject="CloudSentinel Remediation Alert",
            Message=message,
        )
