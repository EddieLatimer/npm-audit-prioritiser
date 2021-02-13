VULNERABILITIES_ORDER = ["critical", "high", "moderate", "low", "info"]


def _get_severity(vulnerability: dict):
    if "severity" not in vulnerability:
        return None
    return vulnerability["severity"]


def _get_vulnerabilities(complete_data: dict):
    if "vulnerabilities" not in complete_data:
        return None
    return complete_data["vulnerabilities"]


def _get_vulnerability(complete_data: dict, name: str):
    vulnerabilities = _get_vulnerabilities(complete_data)
    return vulnerabilities[name]


def _remove_vulnerability(complete_data: dict, name: str):
    vulnerabilities = _get_vulnerabilities(complete_data)
    if not vulnerabilities or name in vulnerabilities:
        del vulnerabilities[name]


def _remove_vulnerabilities(complete_data: dict, names: list):
    for name in names:
        _remove_vulnerability(complete_data, name)


def _get_vulnerability_tallies(complete_data: dict):
    vulnerabilities = _get_vulnerabilities(complete_data)
    vulnerability_tallies = {vulnerability: 0 for vulnerability in VULNERABILITIES_ORDER}
    if not vulnerabilities:
        return vulnerability_tallies

    for vulnerability in vulnerabilities:
        severity = _get_severity(vulnerabilities[vulnerability])
        if severity in VULNERABILITIES_ORDER:
            vulnerability_tallies[severity] += 1

    return vulnerability_tallies


def _get_highest_severity(complete_input: dict):
    vulnerabilities_totals = _get_vulnerability_tallies(complete_input)

    for vulnerability in VULNERABILITIES_ORDER:
        if vulnerability in vulnerabilities_totals and \
                vulnerabilities_totals[vulnerability] > 0:
            return vulnerability
    return None


def filter_on_highest_severity(input_data: dict):
    highest_severity = _get_highest_severity(input_data)
    vulnerabilities = _get_vulnerabilities(input_data)
    if not vulnerabilities:
        return input_data

    to_remove = []
    for vulnerability in vulnerabilities:
        severity = _get_severity(_get_vulnerability(input_data, vulnerability))
        if not severity or severity != highest_severity:
            to_remove += [vulnerability]

    _remove_vulnerabilities(input_data, to_remove)

    return input_data
