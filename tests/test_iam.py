from unittest.mock import MagicMock, patch
from checks.iam import check_excessive_permissions
from checks.iam import check_mfa


@patch("checks.iam.boto3.client")
def test_mfa_detects_user_without_mfa(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "test-user"}]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": []
    }

    findings = check_mfa()

    assert len(findings) == 1
    assert findings[0]["check"] == "IAM User without MFA"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource"] == "test-user"


@patch("checks.iam.boto3.client")
def test_mfa_does_not_flag_user_with_mfa(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "secure-user"}]
    }

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": [
            {"SerialNumber": "arn:aws:iam::123456789012:mfa/test"}
        ]
    }

    findings = check_mfa()

    assert findings == []


@patch("checks.iam.boto3.client")
def test_mfa_handles_multiple_users(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [
            {"UserName": "user-with-mfa"},
            {"UserName": "user-without-mfa"}
        ]
    }

    def mock_list_mfa_devices(UserName):
        if UserName == "user-with-mfa":
            return {"MFADevices": [{"SerialNumber": "test-device"}]}
        return {"MFADevices": []}

    mock_iam.list_mfa_devices.side_effect = mock_list_mfa_devices

    findings = check_mfa()

    assert len(findings) == 1
    assert findings[0]["resource"] == "user-without-mfa"

@patch("checks.iam.boto3.client")
def test_detects_administrator_access(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "admin-test"}]
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "AdministratorAccess",
                "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
            }
        ]
    }

    mock_iam.get_policy.return_value = {
        "Policy": {"DefaultVersionId": "v1"}
    }

    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }
                ]
            }
        }
    }

    mock_iam.list_user_policies.return_value = {
        "PolicyNames": []
    }

    findings = check_excessive_permissions()

    assert any(
        finding["check"] == "IAM User with AdministratorAccess"
        and finding["resource"] == "admin-test"
        for finding in findings
    )

@patch("checks.iam.boto3.client")
def test_detects_wildcard_actions(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "wildcard-test"}]
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [
            {
                "PolicyName": "CustomPolicy",
                "PolicyArn": "arn:aws:iam::123456789012:policy/CustomPolicy"
            }
        ]
    }

    mock_iam.get_policy.return_value = {
        "Policy": {"DefaultVersionId": "v1"}
    }

    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }]
            }
        }
    }

    mock_iam.list_user_policies.return_value = {
        "PolicyNames": []
    }

    findings = check_excessive_permissions()

    assert any(
        finding["check"] == "IAM Policy with Wildcard Actions"
        and finding["resource"] == "wildcard-test"
        for finding in findings
    )

@patch("checks.iam.boto3.client")
def test_detects_service_wildcard_actions(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "wildcard-test"}]
    }

    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": [{
            "PolicyName": "CustomPolicy",
            "PolicyArn": "arn:aws:iam::123456789012:policy/CustomPolicy"
        }]
    }

    mock_iam.get_policy.return_value = {
        "Policy": {"DefaultVersionId": "v1"}
    }

    mock_iam.get_policy_version.return_value = {
        "PolicyVersion": {
            "Document": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "*"
                }]
            }
        }
    }

    mock_iam.list_user_policies.return_value = {"PolicyNames": []}

    findings = check_excessive_permissions()

    assert any(
        finding["check"] == "IAM Policy with Wildcard Actions"
        and finding["resource"] == "wildcard-test"
        for finding in findings
    )

@patch("checks.iam.boto3.client")
def test_detects_inline_policy_wildcard_actions(mock_boto_client):
    mock_iam = MagicMock()
    mock_boto_client.return_value = mock_iam

    mock_iam.list_users.return_value = {
        "Users": [{"UserName": "inline-wildcard-user"}]
    }

    # No attached managed policies
    mock_iam.list_attached_user_policies.return_value = {
        "AttachedPolicies": []
    }

    # User has an inline policy
    mock_iam.list_user_policies.return_value = {
        "PolicyNames": ["InlineAdminPolicy"]
    }

    mock_iam.get_user_policy.return_value = {
        "PolicyDocument": {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
    }

    findings = check_excessive_permissions()

    assert any(
        finding["check"] == "IAM Policy with Wildcard Actions"
        and finding["resource"] == "inline-wildcard-user"
        for finding in findings
    )