#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import ExpandedPyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os


# Usage for pipe masters: ./last.py -l 5h | jq .
# Usage in case of large data set and pivoting page by page: python3 last.py  -l 48h  -m 10 -p 2  | jq .[].Event.info

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download latest events from a MISP instance.')
    parser.add_argument("-l", "--last", required=True, help="can be defined in days, hours, minutes (for example 5d or 12h or 30m).")
    parser.add_argument("-m", "--limit", required=False, default="10", help="Add the limit of records to get (by default, the limit is set to 10)")
    parser.add_argument("-p", "--page", required=False, default="1", help="Add the page to request to paginate over large dataset (by default page is set to 1)")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, aborted.')
        exit(0)

    misp = ExpandedPyMISP(misp_url, misp_key, misp_verifycert)
    result = misp.search(publish_timestamp=args.last, limit=args.limit, page=args.page, pythonify=True)

    if not result:
        print('No results for that time period')
        exit(0)

    if args.output:
        with open(args.output, 'w') as f:
            for r in result:
                f.write(r.to_json() + '\n')
    else:
        for r in result:
            print(r.to_json())
