

def get_severity(vulnerability: dict):
    if "severity" not in vulnerability:
        return None
    return vulnerability["severity"]


def get_vulnerabilities(complete_data: dict):
    if "vulnerabilities" not in complete_data:
        return None
    return complete_data["vulnerabilities"]


def get_highest_severity(complete_input: dict):
    if "metadata" not in complete_input:
        raise ValueError("complete_dict does not contain 'metadata'")
    if not complete_input["metadata"]:
        raise ValueError("complete_input['metadata'] is empty")

    vulnerabilities_totals = complete_input["metadata"]["vulnerabilities"]
    vulnerabilities_order = ["critical", "high", "moderate", "low", "info"]
    for vulnerability in vulnerabilities_order:
        if vulnerability in vulnerabilities_totals and \
                vulnerabilities_totals[vulnerability] > 0:
            return vulnerability
    return None
