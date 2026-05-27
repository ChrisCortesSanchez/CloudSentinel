class FindingParser:
    @staticmethod
    def parse(event: dict) -> dict:
        findings = event.get("detail", {}).get("findings")
        if not findings:
            raise ValueError("Event contains no findings")

        finding = findings[0]
        resources = finding.get("Resources", [])
        if not resources:
            raise ValueError("Finding contains no resources")

        return {
            "finding_id": finding["Id"],
            "resource_arn": resources[0]["Id"],
            "resource_type": resources[0]["Type"],
        }
