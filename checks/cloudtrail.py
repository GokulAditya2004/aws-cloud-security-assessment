import boto3


def check_cloudtrail():
    cloudtrail = boto3.client("cloudtrail")
    response = cloudtrail.describe_trails()

    findings = []

    # No CloudTrail trail
    if not response["trailList"]:
        findings.append({
                "check": "CloudTrail not configured",
                "severity": "HIGH",
                "resource": "AWS Account",
                "risk": (
                    "Without CloudTrail, important AWS API activity may not "
                    "be recorded, making security investigations and auditing "
                    "more difficult."
                ),
                "recommendation": (
                    "Configure AWS CloudTrail for security auditing."
                )
            })

        return findings

    # Check each trail
    for trail in response["trailList"]:
        trail_name = trail["Name"]

        # Check whether logging is enabled
        status = cloudtrail.get_trail_status(
            Name=trail["TrailARN"]
        )

        if not status["IsLogging"]:
            findings.append({
                "check": "CloudTrail logging disabled",
                "severity": "HIGH",
                "resource": trail_name,
                "recommendation": (
                    "Enable logging for the CloudTrail trail."
                )
            })

        # Check multi-region configuration
        if not trail.get("IsMultiRegionTrail", False):
            findings.append({
                "check": "CloudTrail is not multi-region",
                "severity": "MEDIUM",
                "resource": trail_name,
                "recommendation": (
                    "Enable multi-region logging to improve "
                    "security visibility across the AWS account."
                )
            })

    return findings