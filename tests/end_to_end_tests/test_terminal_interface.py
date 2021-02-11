import os
import shutil
import unittest
import json
from hamcrest import assert_that, equal_to
from parameterized import parameterized_class

FILE_DIRECTORY = os.path.dirname(os.path.realpath(__file__)) + "/"
TEST_DATA_PATH = FILE_DIRECTORY + "test_data/"
TEST_DATA_TEMP_PATH = FILE_DIRECTORY + "test_data/temp/"


def run_terminal_command_invoke(_, input_file_path: str, output_file_path: str, flag: str = ""):
    os.system(f"cd {FILE_DIRECTORY}; cd ../../; invoke highest-severity -i {input_file_path} -o {output_file_path} "
              f"{flag} -q")


def run_terminal_command_filter_vulnerabilities(_, input_file_path: str, output_file_path: str, flag: str = ""):
    os.system(f"{FILE_DIRECTORY}../../filter_vulnerabilities.py {input_file_path} {output_file_path} {flag} -q")


def parse_json_file_to_dict(file: str):
    with open(file) as json_file:
        return json.load(json_file)


def assert_json_files_are_equivalent(file: str, expected_file: str):
    assert_that(parse_json_file_to_dict(file), equal_to(parse_json_file_to_dict(expected_file)))


# 'name' is simply for clarity of test failure output
@parameterized_class(('run_terminal_command', 'name'), [
    (run_terminal_command_invoke, "invoke"),
    (run_terminal_command_filter_vulnerabilities, "filter_vulnerabilities")
])
class TestTerminalInterfaces(unittest.TestCase):
    def setUp(self):
        try:
            os.mkdir(TEST_DATA_TEMP_PATH)
        except OSError:
            pass

    def tearDown(self):
        shutil.rmtree(TEST_DATA_TEMP_PATH)

    def test_filtering_on_highest_severity(self):
        input_file = TEST_DATA_PATH + "part-1-input.json"
        output_file = TEST_DATA_TEMP_PATH + "part-1-output.json"
        expected_output_file = TEST_DATA_PATH + "part-1-output.json"

        self.run_terminal_command(input_file, output_file)

        assert_json_files_are_equivalent(output_file, expected_output_file)

    def test_creates_output_directory_if_does_not_exist(self):
        non_existent_directory = TEST_DATA_TEMP_PATH + "non-existent-dir/"
        input_file = TEST_DATA_PATH + "part-1-input.json"
        output_file = non_existent_directory + "part-1-output.json"
        expected_output_file = TEST_DATA_PATH + "part-1-output.json"
        assert_that(not os.path.exists(non_existent_directory))

        self.run_terminal_command(input_file, output_file)

        assert_json_files_are_equivalent(output_file, expected_output_file)

        shutil.rmtree(non_existent_directory)

    def test_filtering_on_highest_severity_terminal_command_with_ignore_fix_available_flag(self):
        input_file = TEST_DATA_PATH + "part-2-input.json"
        output_file = TEST_DATA_TEMP_PATH + "part-2-output.json"
        expected_output_file = TEST_DATA_PATH + "part-2-output.json"

        self.run_terminal_command(input_file, output_file, "--exclude-fix-available")

        assert_json_files_are_equivalent(output_file, expected_output_file)
