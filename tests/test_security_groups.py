from checks.security_groups import find_exposed_services
from unittest.mock import MagicMock, patch
from checks.security_groups import check_security_groups

RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

def find_exposed_services(permission, risky_ports):
    # Detect unrestricted all-protocol rules first
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

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    if from_port is None or to_port is None:
        return []

    public_ipv4 = any(
        item.get("CidrIp") == "0.0.0.0/0"
        for item in permission.get("IpRanges", [])
    )

    public_ipv6 = any(
        item.get("CidrIpv6") == "::/0"
        for item in permission.get("Ipv6Ranges", [])
    )

    if not (public_ipv4 or public_ipv6):
        return []

    return [
        service
        for port, service in risky_ports.items()
        if from_port <= port <= to_port
    ]


RISKY_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL"
}

def test_public_ssh_ipv4():
    permission = {
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    assert find_exposed_services(permission, RISKY_PORTS) == ["SSH"]


def test_public_ssh_ipv6():
    permission = {
        "FromPort": 22,
        "ToPort": 22,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
    }

    assert find_exposed_services(permission, RISKY_PORTS) == ["SSH"]


def test_ssh_inside_port_range():
    permission = {
        "FromPort": 20,
        "ToPort": 25,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
    }

    assert find_exposed_services(permission, RISKY_PORTS) == ["SSH"]


def test_private_ssh_is_not_public():
    permission = {
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}]
    }

    assert find_exposed_services(permission, RISKY_PORTS) == []

@patch("checks.security_groups.boto3.client")
def test_scanner_detects_public_ssh(mock_boto_client):
    mock_ec2 = MagicMock()
    mock_boto_client.return_value = mock_ec2

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-test123",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-test123",
                        "SecurityGroups": [
                            {"GroupId": "sg-test123"}
                        ]
                    }
                ]
            }
        ]
    }

    findings = check_security_groups()

    assert len(findings) == 1
    assert findings[0]["check"] == "Publicly exposed SSH"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource"] == "i-test123"

@patch("checks.security_groups.boto3.client")
def test_scanner_ignores_private_ssh(mock_boto_client):
    mock_ec2 = MagicMock()
    mock_boto_client.return_value = mock_ec2

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-private123",
                "IpPermissions": [
                    {
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-private123",
                        "SecurityGroups": [
                            {"GroupId": "sg-private123"}
                        ]
                    }
                ]
            }
        ]
    }

    findings = check_security_groups()

    assert findings == []

@patch("checks.security_groups.boto3.client")
def test_scanner_detects_public_rdp(mock_boto_client):
    mock_ec2 = MagicMock()
    mock_boto_client.return_value = mock_ec2

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-rdp123",
                "IpPermissions": [
                    {
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-rdp123",
                        "SecurityGroups": [
                            {"GroupId": "sg-rdp123"}
                        ]
                    }
                ]
            }
        ]
    }

    findings = check_security_groups()

    assert len(findings) == 1
    assert findings[0]["check"] == "Publicly exposed RDP"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource"] == "i-rdp123"

def test_public_range_detects_multiple_risky_services():
    permission = {
        "FromPort": 3300,
        "ToPort": 3400,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": []
    }

    assert find_exposed_services(
        permission, RISKY_PORTS
    ) == ["RDP", "MySQL"]

def test_public_all_traffic_rule():
    permission = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        "Ipv6Ranges": []
    }
  
    assert find_exposed_services(
        permission, RISKY_PORTS
    ) == ["ALL TRAFFIC"]

def test_private_all_traffic_rule():
    permission = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
        "Ipv6Ranges": []
    }

    assert find_exposed_services(
        permission, RISKY_PORTS
    ) == []

@patch("checks.security_groups.boto3.client")
def test_scanner_detects_public_all_traffic(mock_boto_client):
    mock_ec2 = MagicMock()
    mock_boto_client.return_value = mock_ec2

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-alltraffic123",
                "IpPermissions": [
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": []
                    }
                ]
            }
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-alltraffic123",
                        "SecurityGroups": [
                            {"GroupId": "sg-alltraffic123"}
                        ]
                    }
                ]
            }
        ]
    }

    findings = check_security_groups()

    assert len(findings) == 1
    assert findings[0]["check"] == "Publicly exposed ALL TRAFFIC"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource"] == "i-alltraffic123"

@patch("checks.security_groups.boto3.client")
def test_scanner_detects_public_ipv6_ssh(mock_boto_client):
    mock_ec2 = MagicMock()
    mock_boto_client.return_value = mock_ec2

    mock_ec2.describe_security_groups.return_value = {
        "SecurityGroups": [
            {
                "GroupId": "sg-ipv6test",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}]
                    }
                ]
            }
        ]
    }

    mock_ec2.describe_instances.return_value = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-ipv6test",
                        "SecurityGroups": [
                            {"GroupId": "sg-ipv6test"}
                        ]
                    }
                ]
            }
        ]
    }

    findings = check_security_groups()

    assert len(findings) == 1
    assert findings[0]["check"] == "Publicly exposed SSH"
    assert findings[0]["severity"] == "HIGH"
    assert findings[0]["resource"] == "i-ipv6test"
