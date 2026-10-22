import boto3
import pytest
from botocore.stub import Stubber

from checks.ec2 import check_ec2_encryption


@pytest.fixture
def ec2_stubber(monkeypatch):
    client = boto3.client(
        "ec2",
        region_name="ap-south-1",
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
    )

    stubber = Stubber(client)

    monkeypatch.setattr(
        "checks.ec2.boto3.client",
        lambda service_name: client,
    )

    with stubber:
        yield stubber


def test_detects_unencrypted_ebs_volume(ec2_stubber):
    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "BlockDeviceMappings": [
                                {
                                    "Ebs": {
                                        "VolumeId": "vol-1234567890abcdef0"
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    )

    ec2_stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [
                {
                    "VolumeId": "vol-1234567890abcdef0",
                    "Encrypted": False,
                }
            ]
        },
        {"VolumeIds": ["vol-1234567890abcdef0"]},
    )

    findings = check_ec2_encryption()

    assert any(
        finding["check"] == "Unencrypted EBS Volume"
        and finding["severity"] == "HIGH"
        for finding in findings
    )


def test_ignores_encrypted_ebs_volume(ec2_stubber):
    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "BlockDeviceMappings": [
                                {
                                    "Ebs": {
                                        "VolumeId": "vol-1234567890abcdef0"
                                    }
                                }
                            ],
                        }
                    ]
                }
            ]
        },
    )

    ec2_stubber.add_response(
        "describe_volumes",
        {
            "Volumes": [
                {
                    "VolumeId": "vol-1234567890abcdef0",
                    "Encrypted": True,
                }
            ]
        },
        {"VolumeIds": ["vol-1234567890abcdef0"]},
    )

    findings = check_ec2_encryption()

    assert findings == []


def test_ignores_instance_without_block_device_mappings(ec2_stubber):
    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "BlockDeviceMappings": [],
                        }
                    ]
                }
            ]
        },
    )

    findings = check_ec2_encryption()

    assert findings == []


def test_ignores_block_device_without_volume_id(ec2_stubber):
    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890abcdef0",
                            "BlockDeviceMappings": [
                                {"Ebs": {}}
                            ],
                        }
                    ]
                }
            ]
        },
    )

    findings = check_ec2_encryption()

    assert findings == []