import boto3


def check_security_groups():
    ec2 = boto3.client("ec2")

    security_groups = ec2.describe_security_groups()["SecurityGroups"]
    instances = ec2.describe_instances()["Reservations"]

    findings = []

    risky_ports = {
        22: "SSH",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL"
    }

    for reservation in instances:
        for instance in reservation["Instances"]:

            instance_id = instance["InstanceId"]

            for sg in instance.get("SecurityGroups", []):

                sg_id = sg["GroupId"]

                matching_sg = next(
                    (
                        group
                        for group in security_groups
                        if group["GroupId"] == sg_id
                    ),
                    None
                )

                if not matching_sg:
                    continue

                for permission in matching_sg["IpPermissions"]:

                    from_port = permission.get("FromPort")

                    if from_port not in risky_ports:
                        continue

                    for ip_range in permission.get("IpRanges", []):

                        if ip_range["CidrIp"] == "0.0.0.0/0":

                            findings.append({
                                "check": f"Publicly exposed {risky_ports[from_port]}",
                                "severity": "HIGH",
                                "resource": instance_id,
                                "recommendation": (
                                    "Restrict access to trusted IP addresses."
                                )
                            })

    return findings