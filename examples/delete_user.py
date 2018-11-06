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
    parser = argparse.ArgumentParser(description='Delete the user with the given id. Keep in mind that disabling users (by setting the disabled flag via an edit) is always prefered to keep user associations to events intact.')
    parser.add_argument("-i", "--user_id", help="The id of the user you want to delete.")
    args = parser.parse_args()

    misp = init(misp_url, misp_key)

    print(misp.delete_user(args.user_id))
