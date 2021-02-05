METADATA = {
    "vulnerabilities": {
        "info": 0,
        "low": 7,
        "moderate": 3,
        "high": 2,
        "critical": 0,
        "total": 12
    },
    "dependencies": {
        "prod": 4,
        "dev": 265,
        "optional": 4,
        "peer": 0,
        "peerOptional": 0,
        "total": 268
    }
}


def generate_vulnerability_message(severity: str):
    return {
        "name": "generated",
        "severity": severity,
        "via": [
            "micromatch"
        ],
        "effects": [
            "chokidar"
        ],
        "range": "1.2.0 - 1.3.2",
        "nodes": [
            "node_modules/anymatch"
        ],
        "fixAvailable": True
    }.copy()


def generate_dict_of_vulnerabilities_messages(names_with_severities: dict):
    return {name: generate_vulnerability_message(severity) for name, severity in names_with_severities.items()}


def generate_top_level_data(vulnerabilities: dict):
    if vulnerabilities is None:
        return dict(auditReportVersion=2, metadata=METADATA.copy())
    return dict(auditReportVersion=2, vulnerabilities=vulnerabilities, metadata=METADATA.copy())
