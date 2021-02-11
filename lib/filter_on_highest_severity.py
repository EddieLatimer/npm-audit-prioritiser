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


def _assert_data_validity(complete_input: dict):
    if "metadata" not in complete_input:
        raise ValueError("complete_dict does not contain 'metadata'")
    if not complete_input["metadata"]:
        raise ValueError("complete_input['metadata'] is empty")


def _get_vulnerability_tallies(complete_data: dict):
    return complete_data["metadata"]["vulnerabilities"]


def _get_highest_severity(complete_input: dict):
    _assert_data_validity(complete_input)

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
        if _get_severity(_get_vulnerability(input_data, vulnerability)) != highest_severity:
            to_remove += [vulnerability]

    _remove_vulnerabilities(input_data, to_remove)

    return input_data
