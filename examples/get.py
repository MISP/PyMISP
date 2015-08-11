#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import url_priv, key_priv
# from keys import url_cert, key_cert
import argparse
import os
import json


# Usage for pipe masters: ./last.py -l 5h | jq .


def init(url, key):
    return PyMISP(url, key, True, 'json')


def get_event(m, event, out=None):
    result = m.get_event(event)
    r = result.json()
    if out is None:
        print(json.dumps(r['Event']) + '\n')
    else:
        with open(out, 'w') as f:
            f.write(json.dumps(r['Event']) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get an event from a MISP instance.')
    parser.add_argument("-e", "--event", required=True, help="Event ID to get.")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abord.')
        exit(0)

    misp = init(url_priv, key_priv)
    # misp = init(url_cert, key_cert)

    get_event(misp, args.event, args.output)
