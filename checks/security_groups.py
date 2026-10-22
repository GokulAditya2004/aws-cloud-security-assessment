import boto3

def find_exposed_services(permission, risky_ports):
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    # Detect unrestricted all-protocol rules
    if permission.get("IpProtocol") == "-1":
        public_ipv4 = any(
            item.get("CidrIp") == "0.0.0.0/0"
            for item in permission.get("IpRanges", [])
        )

        public_ipv6 = any(
            item.get("CidrIpv6") == "::/0"
            for item in permission.get("Ipv6Ranges", [])
        )

        if public_ipv4 or public_ipv6:
            return ["ALL TRAFFIC"]

        return []

    if from_port is None or to_port is None:
        return []

    exposed_services = [
        service
        for port, service in risky_ports.items()
        if from_port <= port <= to_port
    ]

    public_ipv4 = any(
        item.get("CidrIp") == "0.0.0.0/0"
        for item in permission.get("IpRanges", [])
    )

    public_ipv6 = any(
        item.get("CidrIpv6") == "::/0"
        for item in permission.get("Ipv6Ranges", [])
    )

    if public_ipv4 or public_ipv6:
        return exposed_services

    return []

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

                    exposed_services = find_exposed_services(
                        permission,
                        risky_ports
                    )

                    if not exposed_services:
                        continue

                    findings.append({
                        "check": (
                            f"Publicly exposed "
                            f"{', '.join(exposed_services)}"
                        ),
                        "severity": "HIGH",
                        "resource": instance_id,
                        "risk": (
                            "All protocols and ports are accessible from the internet."
                            if "ALL TRAFFIC" in exposed_services
                            else (
                                f"{', '.join(exposed_services)} is accessible from any "
                                "IPv4 or IPv6 address, increasing the risk of "
                                "unauthorized access."
                            )
                        ),
                        "recommendation": (
                            "Restrict inbound access to trusted IP "
                            "addresses and required network ranges."
                        )
                    })

    return findings
