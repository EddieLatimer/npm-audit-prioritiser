from invoke import task
from lib.execute_terminal_input import filter_on_highest_severity

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

    filter_on_highest_severity(input_file, output_file, quiet)
