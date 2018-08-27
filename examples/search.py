#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key,misp_verifycert
import argparse
import os
import json


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')


def search(m, quiet, url, controller, out=None, **kwargs):
    result = m.search(controller, **kwargs)
    if quiet:
        for e in result['response']:
            print('{}{}{}\n'.format(url, '/events/view/', e['Event']['id']))
    elif out is None:
        print(json.dumps(result['response']))
    else:
        with open(out, 'w') as f:
            f.write(json.dumps(result['response']))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get all the events matching a value for a given param.')
    parser.add_argument("-p", "--param", required=True, help="Parameter to search (e.g. category, org, values, type_attribute, etc.)")
    parser.add_argument("-s", "--search", required=True, help="String to search.")
    parser.add_argument("-a", "--attributes", action='store_true', help="Search attributes instead of events")
    parser.add_argument("-q", "--quiet", action='store_true', help="Only display URLs to MISP")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = init(misp_url, misp_key)
    kwargs = {args.param: args.search}

    if args.attributes:
        controller='attributes'
    else:
        controller='events'

    search(misp, args.quiet, misp_url, controller, args.output, **kwargs)
