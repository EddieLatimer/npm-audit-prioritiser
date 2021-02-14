#!/usr/bin/python3
import argparse
from lib.execute_terminal_input import filter_on_highest_severity


def highest_severity(args):
    filter_on_highest_severity(args.input_file_path, args.output_file_path, args.exclude_fix_available, args.quiet)


def set_parser():
    parser = argparse.ArgumentParser(description="Filters vulnerabilities by the highest severity (with the option of "
                                                 "ignoring those marked as fixAvailable).")

    parser.add_argument("input_file_path", help='Path of input json file e.g. "/folder/input_file.json". The input must'
                                                ' be in the format of an `npm audit`.')
    parser.add_argument("output_file_path", help='Path of json file to output result to e.g. '
                                                 '"/folder/output_file.json".')
    parser.add_argument("-e", "--exclude-fix-available",
                        action='store_true',
                        help='remove all vulnerabilities with "fixAvailable" value as True, before filtering on'
                             ' highest severity.')
    parser.add_argument("-q", "--quiet", action='store_true', help='skip all non-error terminal printouts.')
    parser.set_defaults(func=highest_severity)
    return parser


if __name__ == "__main__":
    parse = set_parser()
    args = parse.parse_args()
    args.func(args)
