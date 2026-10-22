from unittest.mock import patch, Mock

from botocore.exceptions import ClientError

from scanner import run_checks, build_report

def test_scanner_continues_after_check_failure():
    def failing_check():
        raise ClientError(
            {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "Access denied"
                }
            },
            "DescribeInstances"
        )

    def successful_check():
        return [{
            "check": "Test Finding",
            "severity": "HIGH",
            "resource": "test-resource",
            "recommendation": "Test recommendation"
        }]

    checks = [
        ("Failing Check", failing_check),
        ("Successful Check", successful_check),
    ]

    findings, errors, successful_count = run_checks(checks)

    assert len(errors) == 1
    assert errors[0]["check"] == "Failing Check"
    assert errors[0]["error"] == "AccessDenied"

    assert len(findings) == 1
    assert findings[0]["check"] == "Test Finding"
    assert successful_count == 1

def test_report_marks_scan_as_partial_when_check_fails():
    findings = [{
        "check": "IAM User without MFA",
        "severity": "HIGH",
        "resource": "test-user",
        "recommendation": "Enable MFA."
    }]

    errors = [{
        "check": "Security Groups",
        "error": "AccessDenied"
    }]

    report = build_report(
        account_id="123456789012",
        findings=findings,
        scan_errors=errors,
        successful_checks=6
    )

    assert report["scan_status"] == "PARTIAL"
    assert report["successful_checks"] == 6
    assert report["failed_checks"] == 1
    assert report["scan"]["total_findings"] == 1
    assert report["summary"]["HIGH"] == 1
    assert report["security_score"] == 85

def test_unexpected_error_does_not_stop_remaining_checks():
    def failing_check():
        raise ValueError("Unexpected test error")

    def successful_check():
        return [{
            "check": "Test Finding",
            "severity": "LOW",
            "resource": "test-resource",
            "recommendation": "Test recommendation"
        }]

    checks = [
        ("Unexpected Failure", failing_check),
        ("Successful Check", successful_check),
    ]

    findings, errors, successful_count = run_checks(checks)

    assert len(findings) == 1
    assert successful_count == 1
    assert len(errors) == 1
    assert errors[0]["check"] == "Unexpected Failure"
    assert errors[0]["error"] == "ValueError"

def test_unexpected_error_marks_report_as_partial():
    findings, errors, successful_count = run_checks([
        ("Broken Check", lambda: 1 / 0),
        ("Working Check", lambda: []),
    ])

    report = build_report(
        account_id="123456789012",
        findings=findings,
        scan_errors=errors,
        successful_checks=successful_count,
    )

    assert report["scan_status"] == "PARTIAL"
    assert report["failed_checks"] == 1
    assert report["successful_checks"] == 1
    assert report["errors"][0]["error"] == "ZeroDivisionError"

