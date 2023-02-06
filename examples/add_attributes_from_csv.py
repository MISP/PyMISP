#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv
from pymisp import PyMISP
from pymisp import ExpandedPyMISP, MISPAttribute
from keys import misp_url, misp_key, misp_verifycert
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import argparse
import urllib3
import requests
requests.packages.urllib3.disable_warnings() 


"""

Sample usage:

python3 add_filetype_object_from_csv.py -e <Event_UUID> -f <formated_file_with_attributes>.csv


Attribute CSV file (aach line is an entry):

value;category;type;comment;to_ids;first_seen;last_seen;tag1;tag2
test.pdf;Payload delivery;filename;Email attachment;0;1970-01-01;1970-01-01;tlp:green;ransomware
127.0.0.1;Network activity;ip-dst;C2 server;1;;;tlp:white;

value = IOC's value
category = its MISP category (https://www.circl.lu/doc/misp/categories-and-types/)
type = its MISP type (https://www.circl.lu/doc/misp/categories-and-types/)
comment = IOC's description
to_ids = Boolean expected (0 = IDS flag not checked // 1 = IDS flag checked)
first_seen = First seen date, if any (left empty if not)
last_seen = Last seen date, if any (left empty if not)
tag = IOC tag, if any 

"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add attributes to a MISP event from a semi-colon formated csv file')
    parser.add_argument("-e", "--event_uuid", required=True, help="Event UUID to update")
    parser.add_argument("-f", "--attr_file", required=True, help="Attribute CSV file path")
    args = parser.parse_args()

    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    f = open(args.attr_file, newline='')
    csv_reader = csv.reader(f, delimiter=";")

    for line in csv_reader:
       value = line[0]
       category = line[1]
       type = line[2]
       comment = line[3]
       ids = line[4]
       fseen = line[5]
       lseen = line[6]
       tags = line[7:]

       misp_attribute = MISPAttribute()
       misp_attribute.value = str(value)
       misp_attribute.category = str(category)
       misp_attribute.type = str(type)
       misp_attribute.comment = str(comment)
       misp_attribute.to_ids = str(ids)
       if fseen != '':
          misp_attribute.first_seen = str(fseen)
       if lseen != '':
          misp_attribute.last_seen = str(lseen)
       for x in tags:
            misp_attribute.add_tag(x)
       r = pymisp.add_attribute(args.event_uuid, misp_attribute)
       print(line)
    print("\nAttributes successfully saved :)")
