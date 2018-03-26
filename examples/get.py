#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json


# Usage for pipe masters: ./last.py -l 5h | jq .

proxies = {
    'http': 'http://127.0.0.1:8123',
    'https': 'http://127.0.0.1:8123',
}

proxies = None


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json', proxies=proxies)


def get_event(m, event, out=None):
    result = m.get_event(event)
    if out is None:
        print(json.dumps(result) + '\n')
    else:
        with open(out, 'w') as f:
            f.write(json.dumps(result) + '\n')

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = init(misp_url, misp_key)

    get_event(misp, args.event, args.output)
