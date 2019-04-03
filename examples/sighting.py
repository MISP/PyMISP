#!/usr/bin/env python
# -*- coding: utf-8 -*-

from pymisp import PyMISP
from keys import misp_url, misp_key, misp_verifycert
import argparse

# For python2 & 3 compat, a bit dirty, but it seems to be the least bad one
try:
    input = raw_input
except NameError:
    pass


def init(url, key):
    return PyMISP(url, key, misp_verifycert, 'json')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Add sighting.')
    parser.add_argument("-f", "--json_file", required=True, help="The name of the json file describing the attribute you want to add sighting to.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    misp.sighting_per_json(args.json_file)
