#!/usr/bin/env python3

import argparse
import json
import os
import linecache
from param_names_extractor import ParamNamesExtractor

FILE_PATHS = {}
MISSING_COUNT = 0
CORRECT_COUNT = 0


def extract_field_names(field_names_data):
    field_names = {}
    for field in field_names_data:
        if field == "functionName":
            continue
        field_name = field_names_data[field]["field_name"]
        if field_name != "N/A":
            field_names[field] = field_name
    return field_names

def extract_line_and_files_from_debug(debug_info):
    param_line_and_file_list = []
    for line in debug_info:
        param_line_and_file_list += extract_file_name_and_lines_from_logline(line)
    return param_line_and_file_list



def extract_file_name_and_lines_from_logline(logline):
    line_and_files = []
    for ln_fl in logline.split("{ "):
        if not ln_fl.startswith("ln:"):
            continue
        ln_fl = ln_fl.split("  ")
        try:
            line = ln_fl[0].split(" ")[1]
            file = ln_fl[2].split(" ")[1]
        except IndexError:
            line = ln_fl[0].split(" ")[1]
            file = ln_fl[0].split(" ")[3]
        if (line, file) not in line_and_files:
            line_and_files.append((line, file))
    return line_and_files


def find_file_path(file, repo_path):
    if file in FILE_PATHS:
        return FILE_PATHS[file]
    for path, _, files in os.walk(repo_path):
        for name in files:
            if name == file:
                file_path = os.path.join(path, name)
                FILE_PATHS[file] = file_path
                return file_path
    return ""


def find_missing_field_names(field_name, line_and_file_list, repo_path):
    missing = []
    for line, file in line_and_file_list:
        file_path = find_file_path(file, repo_path)
        if file_path == "":
            continue
        lines = linecache.getlines(file_path, module_globals=None)[int(line) - 3: int(line) + 3]

        if field_name not in ' '.join(lines):
            missing.append((line, file))
            global MISSING_COUNT
            MISSING_COUNT += 1
        else:
            global CORRECT_COUNT
            CORRECT_COUNT += 1
    return missing


def _main():

    parser = argparse.ArgumentParser(description='Check that condition extractor debug info is real.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-repo_path', '-r', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-json_file', '-j', type=str, help='Json file created by condition extractor', required=True)
    parser.add_argument('-output_file', '-o', type=str, help='Output file', required=False)

    args = parser.parse_args()
    
    include_folder = args.include_folder
    repo_path = args.repo_path
    output_file = args.output_file
    input_file = args.json_file

    extractor = ParamNamesExtractor(include_folder, input_file)
    append_field_names_for_all_functions = extractor.get_field_names_for_all_functions(output_file=output_file if output_file else '')
    
    missing = {}
    for function_data in append_field_names_for_all_functions:
        for param in function_data:
            if param == "functionName":
                continue

            for access in function_data[param]:
                field_name = access["field_name"][-1]
                if field_name == "N/A":
                    continue
                
                line_and_file_list = extract_line_and_files_from_debug(access["debug"])
                missing_fields = find_missing_field_names(field_name, line_and_file_list, repo_path)
                if missing_fields:
                    missing[field_name] = missing_fields

    if output_file:
        with open(output_file, "w") as out_file:
            json.dump(missing, out_file, indent=4)        

    print(f"Correct count: {CORRECT_COUNT}")
    print(f"Missing count: {MISSING_COUNT}")

if __name__ == "__main__":
    _main()
