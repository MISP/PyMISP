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
    parser = argparse.ArgumentParser(description='Edit the email of the user designed by the user_id.')
    parser.add_argument("-i", "--user_id", required=True, help="The name of the json file describing the user you want to modify.")
    parser.add_argument("-e", "--email", help="Email linked to the account.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    print(misp.edit_user(args.user_id, email=args.email))
