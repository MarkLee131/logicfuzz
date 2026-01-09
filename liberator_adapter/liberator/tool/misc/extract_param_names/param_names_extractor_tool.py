#!/usr/bin/env python3

import argparse
from param_names_extractor import ParamNamesExtractor


def _main():

    parser = argparse.ArgumentParser(description='Extract list of exprted function from header files.')
    parser.add_argument('-include_folder', '-i', type=str, help='Folder with header files!', required=True)
    parser.add_argument('-json_file', '-j', type=str, help='Json file created by condition extractor', required=True)
    parser.add_argument('-output_file', '-o', type=str, help='Output file', required=False)

    args = parser.parse_args()
    
    include_folder = args.include_folder
    output_file = args.output_file
    input_file = args.json_file

    extractor = ParamNamesExtractor(include_folder, input_file)
    data = extractor.get_field_names_for_all_functions(output_file=output_file if output_file else '')
    if not output_file:
        print(data)

if __name__ == "__main__":
    _main()
