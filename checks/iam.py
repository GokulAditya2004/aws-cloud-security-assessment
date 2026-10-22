import boto3


def check_mfa():
    iam = boto3.client("iam")
    response = iam.list_users()

    findings = []

    for user in response["Users"]:
        username = user["UserName"]

        mfa = iam.list_mfa_devices(UserName=username)

        if not mfa["MFADevices"]:
            findings.append({
                "check": "IAM User without MFA",
                "severity": "HIGH",
                "resource": username,
                "risk": (
                    "Without MFA, a compromised username and password "
                    "could allow unauthorized access to AWS resources."
                ),
                "recommendation": "Enable MFA for this user."
            })

    return findings


def check_excessive_permissions():
    iam = boto3.client("iam")
    response = iam.list_users()
    findings = []

    def has_wildcard_action(policy_document):
        statements = policy_document.get("Statement", [])

        if isinstance(statements, dict):
            statements = [statements]

        for statement in statements:
            # Only flag permissions that allow actions
            if statement.get("Effect", "Allow") != "Allow":
                continue

            actions = statement.get("Action", [])

            if isinstance(actions, str):
                actions = [actions]

            for action in actions:
                if action == "*" or action.endswith(":*"):
                    return True

        return False

    for user in response["Users"]:
        username = user["UserName"]

        # 1. Check attached managed policies
        policies = iam.list_attached_user_policies(
            UserName=username
        )

        for policy in policies["AttachedPolicies"]:
            policy_name = policy["PolicyName"]

            if policy_name == "AdministratorAccess":
                findings.append({
                    "check": "IAM User with AdministratorAccess",
                    "severity": "HIGH",
                    "resource": username,
                    "recommendation": (
                        "Review administrator privileges and "
                        "apply least-privilege permissions."
                    )
                })

            policy_version = iam.get_policy(
                PolicyArn=policy["PolicyArn"]
            )["Policy"]["DefaultVersionId"]

            policy_document = iam.get_policy_version(
                PolicyArn=policy["PolicyArn"],
                VersionId=policy_version
            )["PolicyVersion"]["Document"]

            if has_wildcard_action(policy_document):
                findings.append({
                    "check": "IAM Policy with Wildcard Actions",
                    "severity": "HIGH",
                    "resource": username,
                    "recommendation": (
                        "Restrict wildcard actions and apply "
                        "least-privilege permissions."
                    )
                })

        # 2. Check inline policies
        inline_policies = iam.list_user_policies(
            UserName=username
        )

        for policy_name in inline_policies["PolicyNames"]:
            policy = iam.get_user_policy(
                UserName=username,
                PolicyName=policy_name
            )

            policy_document = policy["PolicyDocument"]

            if has_wildcard_action(policy_document):
                findings.append({
                    "check": "IAM Policy with Wildcard Actions",
                    "severity": "HIGH",
                    "resource": username,
                    "recommendation": (
                        "Restrict wildcard actions and apply "
                        "least-privilege permissions."
                    )
                })

    return findings

def check_unused_access_keys():
    iam = boto3.client("iam")
    response = iam.list_users()

    findings = []

    for user in response["Users"]:
        username = user["UserName"]

        keys = iam.list_access_keys(
            UserName=username
        )

        for key in keys["AccessKeyMetadata"]:
            if key["Status"] != "Active":
                continue

            last_used = key.get("LastUsedDate")

            if last_used is None:
                findings.append({
                    "check": "IAM Access Key Never Recorded as Used",
                    "severity": "MEDIUM",
                    "resource": username,
                    "risk": (
                        "AWS has no recorded last-used date for this access key. "
                        "The key may be unused, but its necessity should be verified."
                    ),
                    "recommendation": (
                        "Review the key's purpose and usage before deactivating "
                        "or deleting it."
                    )
                })

    return findings