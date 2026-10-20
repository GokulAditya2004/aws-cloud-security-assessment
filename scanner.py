import json
from datetime import datetime, timezone

import boto3

from checks.iam import (
    check_mfa,
    check_excessive_permissions,
    check_unused_access_keys
)
from botocore.exceptions import ClientError, BotoCoreError
from checks.security_groups import check_security_groups
from checks.s3 import check_s3
from checks.cloudtrail import check_cloudtrail
from checks.ec2 import check_ec2_encryption


sts = boto3.client("sts")

identity = sts.get_caller_identity()
account_id = identity["Account"]


findings = []
scan_errors = []

checks = [
    ("IAM MFA", check_mfa),
    ("Security Groups", check_security_groups),
    ("S3 Security", check_s3),
    ("CloudTrail", check_cloudtrail),
    ("IAM Permissions", check_excessive_permissions),
    ("IAM Access Keys", check_unused_access_keys),
    ("EBS Encryption", check_ec2_encryption),
]

for check_name, check_function in checks:
    try:
        findings.extend(check_function())
        print(f"[OK] {check_name} check completed")

    except (ClientError, BotoCoreError) as error:
        error_code = (
            error.response.get("Error", {}).get("Code", "AWS_ERROR")
            if isinstance(error, ClientError)
            else type(error).__name__
        )

        scan_errors.append({
            "check": check_name,
            "error": error_code
        })

        print(f"[ERROR] {check_name}: {error_code}")

severity_counts = {
    "CRITICAL": 0,
    "HIGH": 0,
    "MEDIUM": 0,
    "LOW": 0
}

for finding in findings:
    severity = finding["severity"]
    severity_counts[severity] += 1

severity_penalties = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3
}

score_method = (
    "Starting score: 100. "
    "Subtract a fixed penalty for each finding based on severity. "
    "Minimum score: 0."
)

security_score = 100

for severity, count in severity_counts.items():
    security_score -= severity_penalties[severity] * count

security_score = max(security_score, 0)
if security_score >= 90:
    security_rating = "EXCELLENT"
elif security_score >= 75:
    security_rating = "GOOD"
elif security_score >= 50:
    security_rating = "FAIR"
else:
    security_rating = "POOR"

report = {
    "scan": {
        "account_id": account_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings)
    },
    "security_score": security_score,
    "security_rating": security_rating,
    "summary": severity_counts,
    "findings": findings,
    "scan_status": "PARTIAL" if scan_errors else "COMPLETED",
    "successful_checks": len(checks) - len(scan_errors),
    "failed_checks": len(scan_errors),
    "score_method": score_method,
    "errors": scan_errors
}


print("\n=== AWS SECURITY ASSESSMENT ===")
print("Account:", account_id)
print("Total findings:", len(findings))
print(f"Security Score: {security_score}/100")
print("Security Rating:", security_rating)

print("\n=== SEVERITY SUMMARY ===")

for severity, count in severity_counts.items():
    print(f"{severity}: {count}")

print("\n=== FINDINGS ===")

for finding in findings:
    print(f"\n[{finding['severity']}] {finding['check']}")
    print("Resource:", finding["resource"])

    if "risk" in finding:
        print("Risk:", finding["risk"])

    print("Recommendation:", finding["recommendation"])

with open("reports/security_report.json", "w") as file:
    json.dump(report, file, indent=4)


print("\nReport saved to: reports/security_report.json")