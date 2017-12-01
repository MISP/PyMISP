#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get MISP stuff as CSV.')
    parser.add_argument("-e", "--event_id", help="Event ID to fetch. Without it, it will fetch the whole database.")
    parser.add_argument("-a", "--attribute", nargs='+', help="Attribute column names")
    parser.add_argument("-o", "--object_attribute", nargs='+', help="Object attribute column names")
    parser.add_argument("-t", "--misp_types", nargs='+', help="MISP types to fetch (ip-src, hostname, ...)")
    parser.add_argument("-c", "--context", action='store_true', help="Add event level context (tags...)")
    parser.add_argument("-i", "--ignore", action='store_true', help="Returns the attributes even if the event isn't published, or the attribute doesn't have the to_ids flag")
    parser.add_argument("-f", "--outfile", help="Output file to write the CSV.")

    args = parser.parse_args()
    pymisp = PyMISP(misp_url, misp_key, misp_verifycert, debug=True)
    response = pymisp.get_csv(args.event_id, args.attribute, args.object_attribute, args.misp_types, args.context, args.ignore)

    if args.outfile:
        with open(args.outfile, 'w') as f:
            f.write(response)
    else:
        print(response)
