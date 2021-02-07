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


def generate_metadata(vulnerabilities_summary: dict = None):
    if vulnerabilities_summary is None:
        vulnerabilities_summary = generate_vulnerabilities_summary()
    return {
        "vulnerabilities": vulnerabilities_summary,
        "dependencies": {
            "prod": 4,
            "dev": 265,
            "optional": 4,
            "peer": 0,
            "peerOptional": 0,
            "total": 268
        }
    }


def generate_dict_of_vulnerabilities_messages(names_with_severities: dict):
    return {name: generate_vulnerability_message(severity) for name, severity in names_with_severities.items()}


def generate_vulnerabilities_summary(info: int = 0, low: int = 0, moderate: int = 0,
                                     high: int = 0, critical: int = 0):
    return dict(info=info, low=low, moderate=moderate, high=high, critical=critical,
                total=info+low+moderate+high+critical)


def generate_top_level_data(vulnerabilities: dict, metadata: dict = None):
    if metadata is None:
        metadata = generate_metadata(generate_vulnerabilities_summary(low=7, moderate=3, high=2))
    if vulnerabilities is None:
        return dict(auditReportVersion=2, metadata=metadata.copy())
    return dict(auditReportVersion=2, vulnerabilities=vulnerabilities, metadata=metadata.copy())
