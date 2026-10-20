import boto3


def check_s3():
    s3 = boto3.client("s3")
    response = s3.list_buckets()

    findings = []

    for bucket in response["Buckets"]:
        bucket_name = bucket["Name"]

        # Check public access protection
        try:
            public_access = s3.get_public_access_block(
                Bucket=bucket_name
            )

            config = public_access["PublicAccessBlockConfiguration"]

            if not all(config.values()):
                findings.append({
                    "check": "S3 Public Access Protection",
                    "severity": "HIGH",
                    "resource": bucket_name,
                    "recommendation": "Enable all S3 public access block settings."
                })

        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "check": "S3 Public Access Protection",
                "severity": "HIGH",
                "resource": bucket_name,
                "recommendation": "Configure S3 Block Public Access."
            })

        # Check encryption
        try:
            s3.get_bucket_encryption(
                Bucket=bucket_name
            )

        except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
            findings.append({
                "check": "S3 Bucket Encryption Disabled",
                "severity": "MEDIUM",
                "resource": bucket_name,
                "recommendation": "Enable server-side encryption for the bucket."
            })

    return findings