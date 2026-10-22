import boto3


def check_ec2_encryption():
    ec2 = boto3.client("ec2")
    response = ec2.describe_instances()

    findings = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            for block_device in instance.get("BlockDeviceMappings", []):

                ebs = block_device.get("Ebs")

                if not ebs:
                    continue

                volume_id = ebs.get("VolumeId")

                if not volume_id:
                    continue

                volume = ec2.describe_volumes(
                    VolumeIds=[volume_id]
                )["Volumes"][0]

                if not volume.get("Encrypted", False):

                    findings.append({
                        "check": "Unencrypted EBS Volume",
                        "severity": "HIGH",
                        "resource": f"{instance_id} / {volume_id}",
                        "risk": (
                            "Unencrypted EBS volumes may expose stored data "
                            "if the underlying storage is accessed without authorization."
                        ),
                        "recommendation": (
                            "Use encryption for EBS volumes "
                            "containing sensitive data."
                        )
                    })

    return findings