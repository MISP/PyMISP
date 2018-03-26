#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Example of specifying special attribute type in your search: here yara attribute

from pymisp import PyMISP
from keys import misp_url, misp_key,misp_verifycert
import argparse
import os
import json

def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

def search(m, quiet, url, out=None, custom_type_attribute="yara"):
    controller='attributes'
    result = m.search(controller, type_attribute = custom_type_attribute)
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
    parser.add_argument("-q", "--quiet", action='store_true', help="Only display URLs to MISP")
    parser.add_argument("-o", "--output", help="Output file")

    args = parser.parse_args()

    if args.output is not None and os.path.exists(args.output):
        print('Output file already exists, abort.')
        exit(0)

    misp = init(misp_url, misp_key)

    search(misp, args.quiet, misp_url, args.output)
