# Filter Vulnerabilities

## Description
Given a list of vulnerable third-party dependencies, all with metadata on how severe the vulnerabilities are, 
in the format output from `npm audit`, this program outputs a file that only shows those dependencies with the most 
severe security issues.

There is a flag `--exclude-fix-available` or `-e` to exclude all the vulnerabilities where the `fixAvailable` property 
of the vulnerability is defined and set to `true`.


## Background
[`npm audit`](https://docs.npmjs.com/cli/v7/commands/npm-audit) is a command line tool that queries 
[npm](https://docs.npmjs.com/about-npm) 's database of [security advisories](https://www.npmjs.com/advisories) 
in order to see if any third-party dependencies in a given [Node.js](https://nodejs.org) project are known to be 
vulnerable to [security exploits](https://en.wikipedia.org/wiki/Exploit_(computer_security)).

`npm audit` has a handy subcommand `npm audit fix` that will automatically upgrade dependencies when such upgrades do 
not introduce breaking changes (see [SEMVER](https://semver.org/) if this is a new concept and you'd like to read 
more about it). (Hence why the `--exludeFixAvailable` or `-e` flag)

In order of severity, the possible levels of severity are `info`, `low`, `moderate`, `high` and `critical`, 
where `critical` is the most severe.


## Directions of use

### Running using `filter_vulnerabilites.py`

#### Example usage:
`./filter_vulnerabilities.py tests/end_to_end_tests/test_data/part-1-input.json output.json
--exclude-fix-available`

For more information run `./filter_vulnerabilities.py --help`


### Running using `invoke`

#### Example usage: 
`invoke highest-severity -i tests/end_to_end_tests/test_data/part-2-input.json -o output_file.json -e`

For more information run `invoke --help highest-severity`.

### Compatibility
#### Known working platforms:
- Ubuntu with Python 3.9

## Running tests
`python3.9 -m pip install -r requirements.txt -r tests/requirements.txt`

`python3.9 -m nose `
