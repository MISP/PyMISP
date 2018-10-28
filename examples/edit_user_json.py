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
    parser = argparse.ArgumentParser(description='Edit the user designed by the user_id. If no file is provided, returns a json listing all the fields used to describe a user.')
    parser.add_argument("-i", "--user_id", required=True, help="The name of the json file describing the user you want to modify.")
    parser.add_argument("-f", "--json_file", help="The name of the json file describing your modifications.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    if args.json_file is None:
        print (misp.get_edit_user_fields_list(args.user_id))
    else:
        print(misp.edit_user_json(args.json_file, args.user_id))
