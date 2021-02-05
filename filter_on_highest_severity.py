

def get_severity(vulnerability: dict):
    if "severity" not in vulnerability:
        return None
    return vulnerability["severity"]


def get_vulnerabilities(complete_data: dict):
    if "vulnerabilities" not in complete_data:
        return None
    return complete_data["vulnerabilities"]
