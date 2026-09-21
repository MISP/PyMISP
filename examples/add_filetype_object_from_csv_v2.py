#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
from pymisp import ExpandedPyMISP, MISPObject
from keys import misp_url, misp_key, misp_verifycert
import argparse


"""

Sample usage:

python3 ./add_filetype_object_from_csv_v2.py -e event_id/event_uuid -f files_attributes.csv

files_attributes.csv have at least 2 lines
First line as header containing at least one of [filename;md5;sha1;sha256]
Each other line will be used to create a file MISP Object
Uses ; as delimiter

Note : also works if there are multiple filename columns associated with a unique hash (each column must be named),
"""


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a file type MISP Object starting from attributes in a csv file')
    parser.add_argument("-e", "--event_uuid", required=True, help="Event UUID to update")
    parser.add_argument("-f", "--attr_file", required=True, help="Attribute CSV file path")
    args = parser.parse_args()

    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    f = open(args.attr_file, newline='', encoding="utf-8-sig")
    csv_reader = csv.reader(f, delimiter=";")

    header = next(csv_reader)
    normalized_header = [col.strip().lower() for col in header]
    expected_columns = {"filename", "md5", "sha1", "sha256"}

    matching_columns = {
        index: col for index, col in enumerate(normalized_header) if col in expected_columns
    }
    if not matching_columns:
        raise ValueError(f"File must have at least one of those fields: {', '.join(expected_columns)}")

    print(matching_columns)
    count = 0

    for line, row in enumerate(csv_reader, start=2):
        misp_object = MISPObject(name='file')
        for idx, col in matching_columns.items():
            value = row[idx]
            misp_object.add_attribute(col, value = value)
        r = pymisp.add_object(args.event_uuid, misp_object)
        count = count+1
    print(f'\n{count} Objects created :)')
