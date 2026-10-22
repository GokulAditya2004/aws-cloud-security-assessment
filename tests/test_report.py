from scanner import build_report


def test_report_counts_findings_by_severity():
    findings = [
        {"check": "Check 1", "severity": "HIGH"},
        {"check": "Check 2", "severity": "HIGH"},
        {"check": "Check 3", "severity": "MEDIUM"},
        {"check": "Check 4", "severity": "LOW"},
    ]

    report = build_report("123456789012", findings, [], 7)

    assert report["summary"] == {
        "CRITICAL": 0,
        "HIGH": 2,
        "MEDIUM": 1,
        "LOW": 1,
    }
    assert report["scan"]["total_findings"] == 4


def test_report_calculates_security_score():
    findings = [
        {"check": "Check 1", "severity": "HIGH"},
        {"check": "Check 2", "severity": "MEDIUM"},
        {"check": "Check 3", "severity": "LOW"},
    ]

    report = build_report("123456789012", findings, [], 7)

    # 100 - 15 (HIGH) - 7 (MEDIUM) - 3 (LOW) = 75
    assert report["security_score"] == 75
    assert report["security_rating"] == "GOOD"


def test_security_score_never_goes_below_zero():
    findings = [
        {"check": f"Critical {i}", "severity": "CRITICAL"}
        for i in range(10)
    ]

    report = build_report("123456789012", findings, [], 7)

    assert report["security_score"] == 0
    assert report["security_rating"] == "POOR"


def test_report_marks_failed_scan_as_partial():
    errors = [
        {"check": "CloudTrail", "error": "AccessDenied"},
    ]

    report = build_report("123456789012", [], errors, 6)

    assert report["scan_status"] == "PARTIAL"
    assert report["failed_checks"] == 1
    assert report["successful_checks"] == 6
    assert report["errors"] == errors


def test_report_marks_successful_scan_as_completed():
    report = build_report("123456789012", [], [], 7)

    assert report["scan_status"] == "COMPLETED"
    assert report["failed_checks"] == 0
    assert report["successful_checks"] == 7
    assert report["security_score"] == 100


def test_report_includes_account_and_timestamp():
    report = build_report("123456789012", [], [], 7)

    assert report["scan"]["account_id"] == "123456789012"
    assert report["scan"]["timestamp"]