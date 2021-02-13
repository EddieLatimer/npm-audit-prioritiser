from invoke import task
from lib.filter_on_highest_severity import filter_on_highest_severity
from lib.json_file_io import parse_json_file_to_dict, write_dictionary_to_json_file

HELP = {
    'input-file': 'Path of input json file e.g. "/folder/input_file.json". The file content must be in the format of '
                  'an `npm audit`.',
    'output-file': 'Path of json file to output result to e.g. "/folder/output_file.json".',
    'quiet': 'Skip all non-error terminal printouts.'
}


@task(help=HELP)
def highest_severity(_, input_file="", output_file='output.json', quiet=False):
    """Filters vulnerabilities by the highest severity (with the option of ignoring those marked as fixAvailable)."""

    if input_file == "":
        print("ERROR: Missing essential input-file parameter.")
        return

    try:
        input_file_data = parse_json_file_to_dict(input_file)
    except FileNotFoundError as e:
        print(f"ERROR: Input file '{input_file}' does not exist.")
        return

    output_data = filter_on_highest_severity(input_file_data)

    write_dictionary_to_json_file(output_file, output_data)
    if not quiet:
        print(f"Created output file '{output_file}'.")
