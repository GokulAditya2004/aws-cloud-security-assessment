import boto3
import pytest
from botocore.stub import Stubber

from checks.s3 import check_s3


@pytest.fixture
def s3_stubber(monkeypatch):
    s3 = boto3.client(
        "s3",
        region_name="ap-south-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    stubber = Stubber(s3)
    monkeypatch.setattr("checks.s3.boto3.client", lambda service: s3)

    return s3, stubber


def test_detects_disabled_versioning(s3_stubber):
    s3, stubber = s3_stubber

    stubber.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "test-bucket"}]},
    )
    stubber.add_response(
        "get_bucket_versioning",
        {},
        {"Bucket": "test-bucket"},
    )
    stubber.add_client_error(
        "get_public_access_block",
        service_error_code="NoSuchPublicAccessBlockConfiguration",
        expected_params={"Bucket": "test-bucket"},
    )
    stubber.add_client_error(
        "get_bucket_encryption",
        service_error_code="ServerSideEncryptionConfigurationNotFoundError",
        expected_params={"Bucket": "test-bucket"},
    )

    with stubber:
        findings = check_s3()

    checks = {finding["check"] for finding in findings}
    assert "S3 Bucket Versioning Disabled" in checks


def test_detects_incomplete_public_access_block(s3_stubber):
    s3, stubber = s3_stubber

    stubber.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "test-bucket"}]},
    )
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Enabled"},
        {"Bucket": "test-bucket"},
    )
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "test-bucket"},
    )
    stubber.add_response(
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        },
        {"Bucket": "test-bucket"},
    )

    with stubber:
        findings = check_s3()

    assert any(
        finding["check"] == "S3 Public Access Protection"
        for finding in findings
    )


def test_no_findings_when_checks_are_configured(s3_stubber):
    s3, stubber = s3_stubber

    stubber.add_response(
        "list_buckets",
        {"Buckets": [{"Name": "test-bucket"}]},
    )
    stubber.add_response(
        "get_bucket_versioning",
        {"Status": "Enabled"},
        {"Bucket": "test-bucket"},
    )
    stubber.add_response(
        "get_public_access_block",
        {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        },
        {"Bucket": "test-bucket"},
    )
    stubber.add_response(
        "get_bucket_encryption",
        {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256"
                        }
                    }
                ]
            }
        },
        {"Bucket": "test-bucket"},
    )

    with stubber:
        findings = check_s3()

    assert findings == []
