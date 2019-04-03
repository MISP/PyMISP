#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import os
import json


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def search_sighting(m, context, out=None, **kwargs):

    result = m.sighting_search(context, **kwargs)
    if out is None:
        print(json.dumps(result['response']))
    else:
        with open(out, 'w') as f:
            f.write(json.dumps(result['response']))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get all the events matching a value.')
    parser.add_argument("-c", "--context", default="", help="Context in which to search. Could be empty, attribute or event")
    parser.add_argument("-i", "--id", type=int, help="If context is set, the ID in which the search should be done")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abord.')
        exit(0)

    misp = init(misp_url, misp_key)
    kwargs = {}
    if len(args.context) > 0:
        kwargs['id'] = args.id

    search_sighting(misp, args.context, args.output, **kwargs)
