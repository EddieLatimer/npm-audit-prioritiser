import unittest
from hamcrest import assert_that, is_
from data_generators import generate_vulnerability_message
from filter_on_highest_severity import get_severity


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
