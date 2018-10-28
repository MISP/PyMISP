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
    parser = argparse.ArgumentParser(description='Add  the user described in the given json. If no file is provided, returns a json listing all the fields used to describe a user.')
    parser.add_argument("-f", "--json_file", help="The name of the json file describing the user you want to create.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.json_file is None:
        print (misp.get_add_user_fields_list())
    else:
        print(misp.add_user_json(args.json_file))
