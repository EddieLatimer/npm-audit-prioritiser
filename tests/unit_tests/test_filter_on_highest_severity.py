import unittest
from hamcrest import assert_that, is_
from data_generators import generate_vulnerability_message, generate_top_level_data, \
    generate_dict_of_vulnerabilities_messages, generate_metadata, generate_vulnerabilities_summary
from filter_on_highest_severity import get_severity, get_vulnerabilities, get_highest_severity


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


class TestGetHighestSeverity(unittest.TestCase):
    def test_given_data_with_empty_metadata_then_raises_value_error(self):
        data = generate_top_level_data({}, metadata={})
        self.assertRaises(ValueError, get_highest_severity, data)

    def test_given_data_with_no_metadata_then_raises_value_error(self):
        data = generate_top_level_data({})
        del data["metadata"]
        self.assertRaises(ValueError, get_highest_severity, data)

    def test_given_data_with_metadata_when_all_vulnerabilities_tallies_are_zero_then_return_none(self):
        metadata = generate_metadata()
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_(None))

    def test_given_metadata_with_a_critical_vulnerability_in_tally_then_returns_critical(self):
        vulnerabilities_summary = generate_vulnerabilities_summary(critical=1)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_("critical"))

    def test_given_metadata_with_only_a_low_vulnerability_in_tally_then_returns_low(self):
        vulnerabilities_summary = generate_vulnerabilities_summary(info=1)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_("info"))

    def test_given_metadata_with_high_and_moderate_vulnerabilities_in_tally_then_returns_high(self):
        vulnerabilities_summary = generate_vulnerabilities_summary(high=1, moderate=3)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_("high"))

    def test_given_metadata_with_one_of_each_vulnerability_but_in_opposite_order_then_returns_critical(self):
        vulnerabilities_summary = dict(moderate=1, low=1, total=5, critical=1, info=1, high=1)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_("critical"))

    def test_given_metadata_missing_critical_and_moderate_tallies_from_list_and_with_only_one_low_returns_low(self):
        vulnerabilities_summary = dict(low=1, total=1, info=0, high=0)
        metadata = generate_metadata(vulnerabilities_summary)
        data = generate_top_level_data({}, metadata=metadata)
        assert_that(get_highest_severity(data), is_("low"))
