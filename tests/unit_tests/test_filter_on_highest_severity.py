from copy import deepcopy
import unittest
from hamcrest import assert_that, is_, equal_to
from data_generators import generate_top_level_data, generate_dict_of_vulnerabilities_messages, generate_metadata, \
    generate_all_data, generate_all_data_with_fix_availability
from lib.filter_on_highest_severity import filter_on_highest_severity, remove_vulnerabilities_with_available_fixes


def retrieve_vulnerability_names(top_level_data: dict):
    if not top_level_data:
        return []
    if "vulnerabilities" not in top_level_data:
        return []

    vulnerability_names = []
    for vulnerability in top_level_data["vulnerabilities"]:
        vulnerability_names.append(vulnerability)
    return vulnerability_names


class TestFilterOnHighestSeverity(unittest.TestCase):
    def test_given_only_a_critical_vulnerability_then_returns_that_vulnerability(self):
        data = generate_all_data({"a": "critical"})

        filtered_data = filter_on_highest_severity(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_only_a_low_vulnerability_then_returns_that_vulnerability(self):
        data = generate_all_data({"a": "info"})

        filtered_data = filter_on_highest_severity(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_only_a_high_and_a_moderate_vulnerability_then_removes_moderate_vulnerability(self):
        data = generate_all_data({"a": "moderate", "b": "high"})

        filtered_data = filter_on_highest_severity(deepcopy(data))

        del data["vulnerabilities"]["a"]

        assert_that(filtered_data, equal_to(data))

    def test_given_5_vulnerabilities_of_different_severities_then_returns_only_the_most_sever(self):
        data = generate_all_data({"a": "low", "b": "moderate", "c": "high", "d": "critical", "e": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["d"]))

    def test_given_two_of_each_levels_of_vulnerability_then_returns_only_the_most_sever(self):
        data = generate_all_data({"a": "low",  "b": "moderate",  "c": "high",  "d":  "critical", "e": "info",
                                  "a2": "low", "b2": "moderate", "c2": "high", "d2": "critical", "e2": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["d", "d2"]))

    def test_given_two_of_each_levels_of_vulnerability_except_critical_then_returns_only_the_high_severity_messages(self):
        data = generate_all_data({"a": "low",  "b": "moderate",  "c": "high",  "e": "info",
                                  "a2": "low", "b2": "moderate", "c2": "high", "e2": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["c", "c2"]))

    def test_given_messages_of_info_low_medium_and_moderate_severity_then_returns_only_the_moderate_severity_messages(self):
        data = generate_all_data({"a": "low",  "b": "moderate",  "e": "info",
                                  "a2": "low", "b2": "moderate", "e2": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["b", "b2"]))

    def test_given_two_messages_of_info_and_low_severity_then_returns_only_the_low_severity_messages(self):
        data = generate_all_data({"a": "low", "a2": "low", "e": "info", "e2": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["a", "a2"]))

    def test_given_3_vulnerabilities_all_info_severity_then_returns_all(self):
        data = generate_all_data({"a": "info", "b": "info", "c": "info"})

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["a", "b", "c"]))

    def test_given_no_vulnerabilities_then_vulnerabilities_returned_is_empty(self):
        data = generate_all_data({})
        assert_that(filter_on_highest_severity(data)["vulnerabilities"], is_({}))

    # ================= ERROR CASES =================
    def test_given_vulnerabilities_missing_then_returns_as_given(self):
        data = generate_all_data({})
        del data['vulnerabilities']

        assert_that(filter_on_highest_severity(deepcopy(data)), is_(data))

    def test_given_vulnerability_with_missing_severity_then_gets_removed(self):
        data = generate_all_data({"a": "low"})
        del data['vulnerabilities']["a"]["severity"]
        filtered_data = filter_on_highest_severity(deepcopy(data))

        del data['vulnerabilities']["a"]
        assert_that(filtered_data, is_(data))

    def test_given_only_a_vulnerability_of_unexpected_severity_then_returns_nothing(self):
        vulnerabilities = generate_dict_of_vulnerabilities_messages({"a": "piccolo"})
        vulnerabilities_summary = dict(piccolo=1, moderate=0, low=0, total=1, critical=0, info=0, high=0)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data(vulnerabilities, metadata=metadata)

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to([]))

    def test_given_a_vulnerability_of_unexpected_severity_among_others_then_unexpected_severity_ignored(self):
        vulnerabilities = generate_dict_of_vulnerabilities_messages({"0": "info", "a": "piccolo", "b": "info"})
        vulnerabilities_summary = dict(piccolo=1, moderate=0, low=0, total=2, critical=0, info=1, high=0)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data(vulnerabilities, metadata=metadata)

        filtered_data = filter_on_highest_severity(data)

        assert_that(retrieve_vulnerability_names(filtered_data), equal_to(["0", "b"]))

    def test_given_metadata_missing_critical_and_moderate_tallies_from_list_and_with_only_one_low_returns_low(self):
        vulnerabilities_summary = dict(low=1, total=1, info=0, high=0)
        metadata = generate_metadata(vulnerabilities_summary)
        vulnerabilities = generate_dict_of_vulnerabilities_messages({"a": "low"})
        data = generate_top_level_data(deepcopy(vulnerabilities), metadata=metadata)
        assert_that(filter_on_highest_severity(data), generate_top_level_data(vulnerabilities, metadata=metadata))

    def test_given_a_vulnerability_without_a_severity_then_it_is_removed(self):
        data = generate_all_data({"a": "critical"})

        del data["vulnerabilities"]["a"]["severity"]

        filtered_data = filter_on_highest_severity(deepcopy(data))

        data_with_vulnerability_removed = generate_all_data({"a": "critical"})
        del data_with_vulnerability_removed["vulnerabilities"]["a"]

        assert_that(filtered_data, equal_to(data_with_vulnerability_removed))


def remove_vulnerabilities(data: dict, to_remove: list):
    for vulnerability in to_remove:
        del data["vulnerabilities"][vulnerability]
    return data


class TestRemoveVulnerabilitiesWithAvailableFixes(unittest.TestCase):
    def test_given_no_vulnerabilities_then_it_is_removed(self):
        data = generate_all_data({})

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_missing_vulnerabilities_then_return_given_data(self):
        data = generate_all_data({})

        del data["vulnerabilities"]
        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_only_one_vulnerability_with_an_available_fix_then_it_is_removed(self):
        without_fixes = {}
        with_fixes = {"a": "critical"}
        data = generate_all_data_with_fix_availability(without_fixes, with_fixes)

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        remove_vulnerabilities(data, ["a"])

        assert_that(filtered_data, equal_to(data))

    def test_given_only_one_vulnerability_with_fixavailable_key_missing_then_return_input(self):
        without_fixes = {"a": "critical"}
        with_fixes = {}
        data = generate_all_data_with_fix_availability(without_fixes, with_fixes)
        del data["vulnerabilities"]["a"]["fixAvailable"]

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_only_one_vulnerability_with_no_fix_available_then_return_input(self):
        without_fixes = {"a": "critical"}
        with_fixes = {}
        data = generate_all_data_with_fix_availability(without_fixes, with_fixes)

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        assert_that(filtered_data, equal_to(data))

    def test_given_one_vulnerability_with_fix_and_one_without_then_return_just_one_without(self):
        without_fixes = {"a": "critical"}
        with_fixes = {"b": "critical"}
        data = generate_all_data_with_fix_availability(without_fixes, with_fixes)

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        remove_vulnerabilities(data, ["b"])

        assert_that(filtered_data, equal_to(data))

    def test_given_two_vulnerabilities_with_fixes_and_two_without_then_return_just_ones_without(self):
        without_fixes = {"a": "critical", "b": "critical"}
        with_fixes = {"c": "critical", "d": "critical"}
        data = generate_all_data_with_fix_availability(without_fixes, with_fixes)

        filtered_data = remove_vulnerabilities_with_available_fixes(deepcopy(data))

        remove_vulnerabilities(data, ["c", "d"])

        assert_that(filtered_data, equal_to(data))
