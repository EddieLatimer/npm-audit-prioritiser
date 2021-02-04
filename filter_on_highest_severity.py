

def get_severity(vulnerability: dict):
    if "severity" not in vulnerability:
        return None
    return vulnerability["severity"]
