#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json


# Usage for pipe masters: ./last.py -l 5h | jq .


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def download_last(m, last, out=None):
    result = m.download_last(last)
    if out is None:
        if 'response' in result:
            print(json.dumps(result['response']))
        else:
            print('No results for that time period')
            exit(0)
    else:
        with open(out, 'w') as f:
            f.write(json.dumps(result['response']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Download latest events from a MISP instance.')
    parser.add_argument("-l", "--last", required=True, help="can be defined in days, hours, minutes (for example 5d or 12h or 30m).")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abord.')
        exit(0)

    misp = init(misp_url, misp_key)

    download_last(misp, args.last, args.output)
