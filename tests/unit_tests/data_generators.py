def generate_vulnerability_message(severity: str, with_fix: bool = False):
    fix_available = {
        "name": "generated",
        "version": "4.17.20",
        "isSemVerMajor": True
    }
    if with_fix:
        fix_available = True

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
        "fixAvailable": fix_available
    }.copy()


def generate_dict_of_vulnerabilities_messages(names_with_severities: dict, with_fix: bool = False):
    return {name: generate_vulnerability_message(severity, with_fix) for name, severity in names_with_severities.items()}


def generate_vulnerabilities_summary(info: int = 0, low: int = 0, moderate: int = 0,
                                     high: int = 0, critical: int = 0):
    return dict(info=info, low=low, moderate=moderate, high=high, critical=critical,
                total=info+low+moderate+high+critical)


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


def generate_top_level_data(vulnerabilities: dict, metadata: dict = None):
    if metadata is None:
        metadata = generate_metadata(generate_vulnerabilities_summary(low=7, moderate=3, high=2))
    if vulnerabilities is None:
        return dict(auditReportVersion=2, metadata=metadata.copy())
    return dict(auditReportVersion=2, vulnerabilities=vulnerabilities, metadata=metadata.copy())


def tally_severities(names_with_severities: dict):
    tally = dict(info=0, low=0, moderate=0, high=0, critical=0, total=0)
    for severity in names_with_severities.values():
        tally["total"] += 1
        if severity in tally:
            tally[severity] += 1
    return tally


def generate_all_data(names_with_severities: dict):
    vulnerabilities = generate_dict_of_vulnerabilities_messages(names_with_severities)
    vulnerabilities_summary = tally_severities(names_with_severities)
    metadata = generate_metadata(vulnerabilities_summary)
    return generate_top_level_data(vulnerabilities, metadata=metadata)


def generate_all_data_with_fix_availability(names_with_severities_without_fix: dict, names_with_severities_with_fix: dict):
    vulnerabilities_without_fix = generate_dict_of_vulnerabilities_messages(names_with_severities_without_fix)
    vulnerabilities_with_fix = generate_dict_of_vulnerabilities_messages(names_with_severities_with_fix, True)
    vulnerabilities = vulnerabilities_without_fix | vulnerabilities_with_fix

    vulnerabilities_summary = tally_severities(names_with_severities_without_fix | names_with_severities_with_fix)

    metadata = generate_metadata(vulnerabilities_summary)

    return generate_top_level_data(vulnerabilities, metadata=metadata)
