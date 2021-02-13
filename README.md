# Filter Vulnerabilities

## Description
Given a list of vulnerable third-party dependencies, all with metadata on how severe the vulnerabilities are, 
in the format output from `npm audit`, this program outputs a file that only shows those dependencies with the most 
severe security issues.

## Background
[`npm audit`](https://docs.npmjs.com/cli/v7/commands/npm-audit) is a command line tool that queries 
[npm](https://docs.npmjs.com/about-npm) 's database of [security advisories](https://www.npmjs.com/advisories) 
in order to see if any third-party dependencies in a given [Node.js](https://nodejs.org) project are known to be 
vulnerable to [security exploits](https://en.wikipedia.org/wiki/Exploit_(computer_security)).

In order of severity, the possible levels of severity are `info`, `low`, `moderate`, `high` and `critical`, 
where `critical` is the most severe.

## Compatibility
Known working platforms:
- Ubuntu with Python 3.9
