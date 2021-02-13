from lib.npm_audit_data import NpmAuditData
from lib.json_file_io import parse_json_file_to_dict, write_dictionary_to_json_file


def filter_on_highest_severity(input_file_path: str, output_file_path: str, exclude_auto_fixes: bool, quiet: bool):
    try:
        file_data = parse_json_file_to_dict(input_file_path)
    except FileNotFoundError:
        print(f"ERROR: Input file '{input_file_path}' does not exist.")
        return

    data = NpmAuditData(file_data)

    if exclude_auto_fixes:
        data.remove_vulnerabilities_with_available_fixes()

    data.filter_on_highest_severity()

    write_dictionary_to_json_file(output_file_path, data.get_dictionary())

    if not quiet:
        print(f"Created output file '{output_file_path}'.")
