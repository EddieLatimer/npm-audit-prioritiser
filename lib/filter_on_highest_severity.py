class NpmAuditData:
    VULNERABILITIES_ORDER = ["critical", "high", "moderate", "low", "info"]

    def __init__(self, complete_data: dict):
        self.data = complete_data

    def get_dictionary(self):
        return self.data

    def _get_severity(self, name: str):
        vulnerability = self._get_vulnerability(name)
        if not vulnerability or "severity" not in vulnerability:
            return None
        return vulnerability["severity"]

    def _get_vulnerabilities(self):
        if "vulnerabilities" not in self.data:
            return None
        return self.data["vulnerabilities"]

    def _get_vulnerability(self, name: str):
        vulnerabilities = self._get_vulnerabilities()
        return vulnerabilities[name]

    def _has_available_fix(self, vulnerability_name: str):
        vulnerability = self._get_vulnerability(vulnerability_name)
        if not vulnerability or "fixAvailable" not in vulnerability:
            return False
        if vulnerability["fixAvailable"] is not True:
            return False
        return True

    def _get_vulnerability_tallies(self):
        vulnerability_tallies = {vulnerability: 0 for vulnerability in self.VULNERABILITIES_ORDER}
        vulnerabilities = self._get_vulnerabilities()
        if not vulnerabilities:
            return vulnerability_tallies

        for vulnerability in vulnerabilities:
            severity = self._get_severity(vulnerability)
            if severity in self.VULNERABILITIES_ORDER:
                vulnerability_tallies[severity] += 1

        return vulnerability_tallies

    def _get_highest_severity(self):
        vulnerabilities_totals = self._get_vulnerability_tallies()

        for vulnerability in self.VULNERABILITIES_ORDER:
            if vulnerability in vulnerabilities_totals and \
                    vulnerabilities_totals[vulnerability] > 0:
                return vulnerability
        return None

    def _remove_vulnerability(self, name: str):
        vulnerabilities = self._get_vulnerabilities()
        if vulnerabilities and name in vulnerabilities:
            del vulnerabilities[name]

    def _remove_vulnerabilities(self, names: list):
        for name in names:
            self._remove_vulnerability(name)

    def remove_vulnerabilities_with_available_fixes(self):
        vulnerabilities = self._get_vulnerabilities()
        if not vulnerabilities:
            return self.data

        to_remove = []
        for vulnerability in vulnerabilities:
            if self._has_available_fix(vulnerability):
                to_remove += [vulnerability]

        self._remove_vulnerabilities(to_remove)

        return self.data

    def filter_on_highest_severity(self):
        highest_severity = self._get_highest_severity()
        vulnerabilities = self._get_vulnerabilities()
        if not vulnerabilities:
            return self.data

        to_remove = []
        for vulnerability in vulnerabilities:
            severity = self._get_severity(vulnerability)
            if not severity or severity != highest_severity:
                to_remove += [vulnerability]

        self._remove_vulnerabilities(to_remove)

        return self.data
