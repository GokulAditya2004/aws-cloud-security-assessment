import boto3
import pytest
from botocore.stub import Stubber

from checks.cloudtrail import check_cloudtrail


@pytest.fixture
def cloudtrail_stubber(monkeypatch):
    client = boto3.client(
        "cloudtrail",
        region_name="ap-south-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    stubber = Stubber(client)

    monkeypatch.setattr(
        "checks.cloudtrail.boto3.client",
        lambda service_name: client,
    )

    with stubber:
        yield stubber


def test_detects_missing_cloudtrail(cloudtrail_stubber):
    cloudtrail_stubber.add_response(
        "describe_trails",
        {"trailList": []},
    )

    findings = check_cloudtrail()

    assert any(
        finding["check"] == "CloudTrail not configured"
        and finding["severity"] == "HIGH"
        for finding in findings
    )


def test_detects_disabled_logging(cloudtrail_stubber):
    cloudtrail_stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "test-trail",
                    "TrailARN": (
                        "arn:aws:cloudtrail:ap-south-1:"
                        "123456789012:trail/test-trail"
                    ),
                    "IsMultiRegionTrail": True,
                }
            ]
        },
    )

    cloudtrail_stubber.add_response(
        "get_trail_status",
        {"IsLogging": False},
        {"Name": (
            "arn:aws:cloudtrail:ap-south-1:"
            "123456789012:trail/test-trail"
        )},
    )

    findings = check_cloudtrail()

    assert any(
        finding["check"] == "CloudTrail logging disabled"
        and finding["severity"] == "HIGH"
        for finding in findings
    )


def test_detects_single_region_trail(cloudtrail_stubber):
    cloudtrail_stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "test-trail",
                    "TrailARN": (
                        "arn:aws:cloudtrail:ap-south-1:"
                        "123456789012:trail/test-trail"
                    ),
                    "IsMultiRegionTrail": False,
                }
            ]
        },
    )

    cloudtrail_stubber.add_response(
        "get_trail_status",
        {"IsLogging": True},
        {"Name": (
            "arn:aws:cloudtrail:ap-south-1:"
            "123456789012:trail/test-trail"
        )},
    )

    findings = check_cloudtrail()

    assert any(
        finding["check"] == "CloudTrail is not multi-region"
        and finding["severity"] == "MEDIUM"
        for finding in findings
    )


def test_no_findings_for_healthy_trail(cloudtrail_stubber):
    cloudtrail_stubber.add_response(
        "describe_trails",
        {
            "trailList": [
                {
                    "Name": "test-trail",
                    "TrailARN": (
                        "arn:aws:cloudtrail:ap-south-1:"
                        "123456789012:trail/test-trail"
                    ),
                    "IsMultiRegionTrail": True,
                }
            ]
        },
    )

    cloudtrail_stubber.add_response(
        "get_trail_status",
        {"IsLogging": True},
        {"Name": (
            "arn:aws:cloudtrail:ap-south-1:"
            "123456789012:trail/test-trail"
        )},
    )

    findings = check_cloudtrail()

    assert findings == []