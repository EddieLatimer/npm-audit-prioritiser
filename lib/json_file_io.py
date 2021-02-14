import os
import json


def parse_json_file_to_dict(file: str):
    with open(file) as json_file:
        return json.load(json_file)


def write_dictionary_to_json_file(file_name: str, dictionary: dict):
    if os.path.dirname(file_name) != "":
        os.makedirs(os.path.dirname(file_name), exist_ok=True)
    with open(file_name, 'w', encoding='utf-8') as outfile:
        json.dump(dictionary, outfile, ensure_ascii=False, indent=4)
