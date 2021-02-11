from lib.filter_on_highest_severity import filter_on_highest_severity as _filter_on_highest_severity, \
    remove_vulnerabilities_with_available_fixes
from lib.json_file_io import parse_json_file_to_dict, write_dictionary_to_json_file


def filter_on_highest_severity(input_file_path: str, output_file_path: str, exclude_fix_available: bool, quiet: bool):
    try:
        data = parse_json_file_to_dict(input_file_path)
    except FileNotFoundError:
        print(f"ERROR: Input file '{input_file_path}' does not exist.")
        return

    if exclude_fix_available:
        data = remove_vulnerabilities_with_available_fixes(data)

    filtered_data = _filter_on_highest_severity(data)

    write_dictionary_to_json_file(output_file_path, filtered_data)

    if not quiet:
        print(f"Created output file '{output_file_path}'.")
