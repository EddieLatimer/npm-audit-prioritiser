import unittest
from hamcrest import assert_that, is_
from data_generators import generate_vulnerability_message, generate_top_level_data, \
    generate_dict_of_vulnerabilities_messages
from filter_on_highest_severity import get_severity, get_vulnerabilities


class TestGetSeverity(unittest.TestCase):
    def test_given_message_with_critical_severity_then_returns_critical(self):
        message = generate_vulnerability_message('critical')
        assert_that(get_severity(message), is_('critical'))

    def test_given_message_with_low_severity_then_returns_low(self):
        message = generate_vulnerability_message('low')
        assert_that(get_severity(message), is_('low'))

    # error case
    def test_given_message_with_no_severity_key_then_returns_none(self):
        message = generate_vulnerability_message('any').copy()
        del message["severity"]
        assert_that(get_severity(message), is_(None))


class TestGetVulnerabilities(unittest.TestCase):
    def test_given_data_has_empty_vulnerabilities_list_then_returns_empty_set(self):
        data = generate_top_level_data({})
        assert_that(get_vulnerabilities(data), is_({}))

    def test_given_data_has_no_vulnerabilities_list_then_returns_none(self):
        data = generate_top_level_data(None)
        assert_that(get_vulnerabilities(data), is_(None))

    def test_given_data_with_vulnerabilities_then_returns_them(self):
        vulnerabilities = generate_dict_of_vulnerabilities_messages({"a": "low", "b": "medium", "c": "high"})
        data = generate_top_level_data(vulnerabilities)
        assert_that(get_vulnerabilities(data), is_(vulnerabilities))
