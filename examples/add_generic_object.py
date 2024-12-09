#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
from pymisp import ExpandedPyMISP
from pymisp.tools import GenericObjectGenerator
from keys import misp_url, misp_key, misp_verifycert
import argparse

"""
Sample usage:
./add_generic_object.py -e 5065 -t email -l '[{"to": "undisclosed@ppp.com"}, {"to": "second.to@mail.com"}]'
"""

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a MISP Object selectable by type starting from a dictionary')
    parser.add_argument("-e", "--event", required=True, help="Event ID to update")
    parser.add_argument("-t", "--type", required=True, help="Type of the generic object")
    parser.add_argument("-l", "--attr_list", required=True, help="List of attributes")
    args = parser.parse_args()

    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)

    misp_object = GenericObjectGenerator(args.type.replace("|", "-"))
    misp_object.generate_attributes(json.loads(args.attr_list))
    r = pymisp.add_object(args.event, misp_object)
