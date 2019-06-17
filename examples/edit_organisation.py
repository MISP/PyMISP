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
    parser = argparse.ArgumentParser(description='Edit the email of the organisation designed by the organisation_id.')
    parser.add_argument("-i", "--organisation_id", required=True, help="The name of the json file describing the organisation you want to modify.")
    parser.add_argument("-e", "--email", help="Email linked to the organisation.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    print(misp.edit_organisation(args.organisation_id, email=args.email))
