#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get MISP stuff as CSV.')
    parser.add_argument("-e", "--event_id", help="Event ID to fetch. Without it, it will fetch the whole database.")
    parser.add_argument("-a", "--attribute", nargs='+', help="Attribute column names")
    parser.add_argument("-o", "--object_attribute", nargs='+', help="Object attribute column names")
    parser.add_argument("-t", "--misp_types", nargs='+', help="MISP types to fetch (ip-src, hostname, ...)")
    parser.add_argument("-c", "--context", action='store_true', help="Add event level context (tags...)")
    parser.add_argument("-f", "--outfile", help="Output file to write the CSV.")

    args = parser.parse_args()
    pymisp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    attr = []
    if args.attribute:
        attr += args.attribute
    if args.object_attribute:
        attr += args.object_attribute
    if not attr:
        attr = None
    print(args.context)
    response = pymisp.search(return_format='csv', eventid=args.event_id, requested_attributes=attr,
                             type_attribute=args.misp_types, include_context=args.context)

    if args.outfile:
        with open(args.outfile, 'w') as f:
            f.write(response)
    else:
        print(response)
