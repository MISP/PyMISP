#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse
import json

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Get statistics from tags.')
    parser.add_argument("-p", "--percentage", action='store_true', default=None, help="An optional field, if set, it will return the results in percentages, otherwise it returns exact count.")
    parser.add_argument("-n", "--namesort", action='store_true', default=None, help="An optional field, if set, values are sort by the namespace, otherwise the sorting will happen on the value.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    stats = misp.get_tags_statistics(args.percentage, args.namesort)
    print(json.dumps(stats))
