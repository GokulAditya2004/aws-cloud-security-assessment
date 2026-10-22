import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, BotoCoreError

from checks.iam import (
    check_mfa,
    check_excessive_permissions,
    check_unused_access_keys,
)
from checks.security_groups import check_security_groups
from checks.s3 import check_s3
from checks.cloudtrail import check_cloudtrail
from checks.ec2 import check_ec2_encryption


CHECKS = [
    ("IAM MFA", check_mfa),
    ("Security Groups", check_security_groups),
    ("S3 Security", check_s3),
    ("CloudTrail", check_cloudtrail),
    ("IAM Permissions", check_excessive_permissions),
    ("IAM Access Keys", check_unused_access_keys),
    ("EBS Encryption", check_ec2_encryption),
]

SEVERITY_PENALTIES = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 7,
    "LOW": 3,
}

SCORE_METHOD = (
    "Starting score: 100. "
    "Subtract a fixed penalty for each finding based on severity. "
    "Minimum score: 0."
)


def get_account_id(sts_client=None):
    """Return the AWS account ID or exit cleanly if STS identity lookup fails."""
    if sts_client is None:
        sts_client = boto3.client("sts")

    try:
        identity = sts_client.get_caller_identity()
        return identity["Account"]
    except (ClientError, BotoCoreError) as error:
        error_code = (
            error.response.get("Error", {}).get("Code", "AWS_ERROR")
            if isinstance(error, ClientError)
            else type(error).__name__
        )
        print(f"[FATAL] Unable to identify AWS account: {error_code}")
        raise SystemExit(1) from error


def run_checks(checks_to_run=None):
    """Run each security check independently and collect findings and errors."""
    if checks_to_run is None:
        checks_to_run = CHECKS

    findings = []
    scan_errors = []
    successful_checks = 0

    for check_name, check_function in checks_to_run:
        try:
            check_findings = check_function()
            findings.extend(check_findings)
            successful_checks += 1
            print(f"[OK] {check_name} check completed")

        except (ClientError, BotoCoreError) as error:
            error_code = (
                error.response.get("Error", {}).get("Code", "AWS_ERROR")
                if isinstance(error, ClientError)
                else type(error).__name__
            )

            scan_errors.append({
                "check": check_name,
                "error": error_code,
            })
            print(f"[ERROR] {check_name}: {error_code}")

        except Exception as error:
            scan_errors.append({
                "check": check_name,
                "error": type(error).__name__
            })
            print(f"[ERROR] {check_name}: {type(error).__name__}")

    return findings, scan_errors, successful_checks


def build_report(account_id, findings, scan_errors, successful_checks):
    """Build the JSON-serializable assessment report."""
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.get("severity")
        if severity in severity_counts:
            severity_counts[severity] += 1

    security_score = 100
    for severity, count in severity_counts.items():
        security_score -= SEVERITY_PENALTIES[severity] * count
    security_score = max(security_score, 0)

    if security_score >= 90:
        security_rating = "EXCELLENT"
    elif security_score >= 75:
        security_rating = "GOOD"
    elif security_score >= 50:
        security_rating = "FAIR"
    else:
        security_rating = "POOR"

    return {
        "scan": {
            "account_id": account_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_findings": len(findings),
        },
        "security_score": security_score,
        "security_rating": security_rating,
        "summary": severity_counts,
        "findings": findings,
        "scan_status": "PARTIAL" if scan_errors else "COMPLETED",
        "successful_checks": successful_checks,
        "failed_checks": len(scan_errors),
        "score_method": SCORE_METHOD,
        "errors": scan_errors,
    }


def main(output_path="reports/security_report.json"):
    """Run the assessment, print the summary, and save the JSON report."""
    account_id = get_account_id()
    findings, scan_errors, successful_checks = run_checks()
    report = build_report(
        account_id=account_id,
        findings=findings,
        scan_errors=scan_errors,
        successful_checks=successful_checks,
    )

    print("\n=== AWS SECURITY ASSESSMENT ===")
    print("Account:", account_id)
    print("Total findings:", len(findings))
    print(f"Security Score: {report['security_score']}/100")
    print("Security Rating:", report["security_rating"])

    print("\n=== SEVERITY SUMMARY ===")
    for severity, count in report["summary"].items():
        print(f"{severity}: {count}")

    print("\n=== FINDINGS ===")
    for finding in findings:
        print(f"\n[{finding['severity']}] {finding['check']}")
        print("Resource:", finding.get("resource", "N/A"))
        if "risk" in finding:
            print("Risk:", finding["risk"])
        print("Recommendation:", finding.get("recommendation", "N/A"))

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\nReport saved to: {destination}")
    return report


if __name__ == "__main__":
    main()
