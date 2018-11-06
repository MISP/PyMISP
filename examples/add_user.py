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
    parser = argparse.ArgumentParser(description='Add a new user by setting the mandory fields.')
    parser.add_argument("-e", "--email", required=True, help="Email linked to the account.")
    parser.add_argument("-o", "--org_id", required=True, help="Organisation linked to the user.")
    parser.add_argument("-r", "--role_id", required=True, help="Role linked to the user.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    print (misp.add_user(args.email, args.org_id, args.role_id))
